package provider

import (
	"reflect"
	"strings"
	"testing"
)

func TestNames_AreSortedAndMatchDefinitions(t *testing.T) {
	names := Names()
	definitions := Definitions()
	if len(names) != len(definitions) {
		t.Fatalf("Names returned %d entries, Definitions returned %d", len(names), len(definitions))
	}

	definitionNames := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		definitionNames[definition.Name] = true
	}
	for i, name := range names {
		if i > 0 && names[i-1] > name {
			t.Fatalf("Names is not sorted: %v", names)
		}
		if !definitionNames[name] {
			t.Fatalf("provider %q has no definition", name)
		}
	}
}

func TestDefault_IsCompiledOrEmpty(t *testing.T) {
	name := Default()
	names := Names()
	if len(names) == 0 {
		if name != "" {
			t.Fatalf("Default() = %q with an empty catalog", name)
		}
		return
	}
	if name != names[0] && name != DefaultName {
		t.Fatalf("Default() = %q, compiled names = %v", name, names)
	}
	for _, compiled := range names {
		if name == compiled {
			return
		}
	}
	t.Fatalf("Default() = %q is not compiled: %v", name, names)
}

func TestNew_UnknownProviderPreservesInput(t *testing.T) {
	_, err := New("MissingProvider", nil)
	if err == nil || err.Error() != "unsupported DNS provider: MissingProvider" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefinitions_ReturnDefensiveCopies(t *testing.T) {
	definitions := Definitions()
	if len(definitions) == 0 {
		return
	}
	if len(definitions[0].Fields) == 0 {
		t.Fatal("expected the first compiled provider to have a credential field")
	}
	wantDefinition := definitions[0]
	wantField := definitions[0].Fields[0]

	definitions[0].Name = "mutated"
	definitions[0].Fields[0].Key = "MUTATED"

	fresh := Definitions()
	if fresh[0].Name != wantDefinition.Name {
		t.Fatalf("definition mutation leaked into registry: got %q, want %q", fresh[0].Name, wantDefinition.Name)
	}
	if fresh[0].Fields[0] != wantField {
		t.Fatalf("field mutation leaked into registry: got %#v, want %#v", fresh[0].Fields[0], wantField)
	}
}

func TestFieldByKey_ReturnsCompiledMetadata(t *testing.T) {
	for _, definition := range Definitions() {
		for _, want := range definition.Fields {
			got, ok := FieldByKey(want.Key)
			if !ok {
				t.Fatalf("FieldByKey(%q) did not find compiled field", want.Key)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("FieldByKey(%q) = %#v, want %#v", want.Key, got, want)
			}
		}
	}
	if _, ok := FieldByKey("REMOVED_PROVIDER_KEY"); ok {
		t.Fatal("FieldByKey found an unknown field")
	}
}

func TestRegistry_ExcludesRemovedProviders(t *testing.T) {
	for _, removed := range []string{"dnspod", "namedotcom", "vultr"} {
		for _, name := range Names() {
			if strings.EqualFold(name, removed) {
				t.Fatalf("removed provider %q is still registered", removed)
			}
		}
	}
}
