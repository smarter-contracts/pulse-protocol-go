package ipfs

import (
	"testing"

	ipld "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/node/basicnode"
)

// buildTestNode constructs an IPLD map:
//
//	{"name": "alice", "age": 30, "data": <bytes 0xdead>}
func buildTestNode(t *testing.T) ipld.Node {
	t.Helper()
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(3)
	if err != nil {
		t.Fatalf("BeginMap: %v", err)
	}

	_ = ma.AssembleKey().AssignString("name")
	_ = ma.AssembleValue().AssignString("alice")

	_ = ma.AssembleKey().AssignString("age")
	_ = ma.AssembleValue().AssignInt(30)

	_ = ma.AssembleKey().AssignString("data")
	_ = ma.AssembleValue().AssignBytes([]byte{0xde, 0xad})

	if err := ma.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return nb.Build()
}

// ── MustString ────────────────────────────────────────────────────────────────

func TestMustString_Success(t *testing.T) {
	node := buildTestNode(t)

	got, err := MustString(node, "name")
	if err != nil {
		t.Fatalf("MustString(name) error: %v", err)
	}
	if got != "alice" {
		t.Errorf("MustString(name) = %q, want %q", got, "alice")
	}
}

func TestMustString_MissingKey(t *testing.T) {
	node := buildTestNode(t)

	_, err := MustString(node, "missing")
	if err == nil {
		t.Error("MustString(missing) expected error, got nil")
	}
}

func TestMustString_WrongType(t *testing.T) {
	node := buildTestNode(t)

	_, err := MustString(node, "age")
	if err == nil {
		t.Error("MustString(age) on int field expected error, got nil")
	}
}

// ── MustInt ───────────────────────────────────────────────────────────────────

func TestMustInt_Success(t *testing.T) {
	node := buildTestNode(t)

	got, err := MustInt(node, "age")
	if err != nil {
		t.Fatalf("MustInt(age) error: %v", err)
	}
	if got != 30 {
		t.Errorf("MustInt(age) = %d, want %d", got, 30)
	}
}

func TestMustInt_MissingKey(t *testing.T) {
	node := buildTestNode(t)

	_, err := MustInt(node, "missing")
	if err == nil {
		t.Error("MustInt(missing) expected error, got nil")
	}
}

func TestMustInt_WrongType(t *testing.T) {
	node := buildTestNode(t)

	_, err := MustInt(node, "name")
	if err == nil {
		t.Error("MustInt(name) on string field expected error, got nil")
	}
}

// ── MustStringList ────────────────────────────────────────────────────────────

// buildStringListNode constructs an IPLD map:
//
//	{"tags": ["alpha","beta","gamma"], "notalist": "just a string", "empty": []}
func buildStringListNode(t *testing.T) ipld.Node {
	t.Helper()
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(3)
	if err != nil {
		t.Fatalf("BeginMap: %v", err)
	}

	_ = ma.AssembleKey().AssignString("tags")
	la, err := ma.AssembleValue().BeginList(3)
	if err != nil {
		t.Fatalf("BeginList(tags): %v", err)
	}
	_ = la.AssembleValue().AssignString("alpha")
	_ = la.AssembleValue().AssignString("beta")
	_ = la.AssembleValue().AssignString("gamma")
	if err := la.Finish(); err != nil {
		t.Fatalf("Finish(tags): %v", err)
	}

	_ = ma.AssembleKey().AssignString("notalist")
	_ = ma.AssembleValue().AssignString("just a string")

	_ = ma.AssembleKey().AssignString("empty")
	la2, err := ma.AssembleValue().BeginList(0)
	if err != nil {
		t.Fatalf("BeginList(empty): %v", err)
	}
	if err := la2.Finish(); err != nil {
		t.Fatalf("Finish(empty): %v", err)
	}

	if err := ma.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return nb.Build()
}

func TestMustStringList_Success(t *testing.T) {
	node := buildStringListNode(t)

	got, err := MustStringList(node, "tags")
	if err != nil {
		t.Fatalf("MustStringList(tags) error: %v", err)
	}
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("MustStringList(tags) len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("MustStringList(tags)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMustStringList_EmptyList(t *testing.T) {
	node := buildStringListNode(t)

	got, err := MustStringList(node, "empty")
	if err != nil {
		t.Fatalf("MustStringList(empty) error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("MustStringList(empty) = %v, want empty slice", got)
	}
}

func TestMustStringList_MissingKey(t *testing.T) {
	node := buildStringListNode(t)

	_, err := MustStringList(node, "missing")
	if err == nil {
		t.Error("MustStringList(missing) expected error, got nil")
	}
}

func TestMustStringList_WrongType(t *testing.T) {
	node := buildStringListNode(t)

	_, err := MustStringList(node, "notalist")
	if err == nil {
		t.Error("MustStringList(notalist) on string field expected error, got nil")
	}
}

// ── MustBytes ─────────────────────────────────────────────────────────────────

func TestMustBytes_Success(t *testing.T) {
	node := buildTestNode(t)

	got, err := MustBytes(node, "data")
	if err != nil {
		t.Fatalf("MustBytes(data) error: %v", err)
	}
	if len(got) != 2 || got[0] != 0xde || got[1] != 0xad {
		t.Errorf("MustBytes(data) = %x, want dead", got)
	}
}

func TestMustBytes_MissingKey(t *testing.T) {
	node := buildTestNode(t)

	_, err := MustBytes(node, "missing")
	if err == nil {
		t.Error("MustBytes(missing) expected error, got nil")
	}
}

func TestMustBytes_WrongType(t *testing.T) {
	node := buildTestNode(t)

	_, err := MustBytes(node, "name")
	if err == nil {
		t.Error("MustBytes(name) on string field expected error, got nil")
	}
}
