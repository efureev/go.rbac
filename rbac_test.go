package rbac

import (
	"fmt"
	"strconv"
	"testing"
)

var (
	rA = NewRole("role-a")
	pA = NewPermission("permission-a")
	rB = NewRole("role-b")
	pB = NewPermission("permission-b")
	rC = NewRole("role-c")
	pC = NewPermission("permission-c")
)

func assert(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func init() {
	rA.Assign(pA)
	rB.Assign(pB)
	rC.Assign(pC)
}

func TestRBAC_Add(t *testing.T) {
	rbac := New()
	assert(t, rbac.Add(rA))
	if err := rbac.Add(rA); err != ErrRoleExist {
		t.Error("A role can not be added")
	}
	assert(t, rbac.Add(rB))
	assert(t, rbac.Add(rC))
}

func TestRBAC_GetRoles(t *testing.T) {
	rbac := New()

	assert(t, rbac.Add(rB))
	assert(t, rbac.Add(rC))

	roles := rbac.GetRoles()
	if 2 != len(roles) {
		t.Error("roles must to be 2")
	}
}

func TestRBAC_GetRole(t *testing.T) {
	rbac := New()

	assert(t, rbac.Add(rA))
	assert(t, rbac.Add(rC))

	assert(t, rbac.SetParent("role-c", "role-a"))

	role, parents, err := rbac.GetRole(`role-c`)

	assert(t, err)
	if 1 != len(parents) {
		t.Error("role must only 1 parent")
	}

	if `role-c` != role.ID() {
		t.Error("role must named as 'role-c'")
	}

	role, parents, err = rbac.GetRole(`role-d`)

	if err != ErrRoleNotExist {
		t.Fatal(`Here have to be an Error`)
	}

	if role != nil {
		t.Fatal(`Must be NIL`)
	}
	if parents != nil {
		t.Fatal(`Must be NIL`)
	}
}

func TestRBAC_GetRemove(t *testing.T) {
	rbac := New()

	assert(t, rbac.Add(rA))
	assert(t, rbac.Add(rB))
	assert(t, rbac.Add(rC))

	assert(t, rbac.SetParent("role-c", "role-a"))
	assert(t, rbac.SetParent("role-a", "role-b"))

	if r, parents, err := rbac.GetRole("role-a"); err != nil {
		t.Fatal(err)
	} else if r.ID() != "role-a" {
		t.Fatalf("[role-a] does not match %s", r.ID())
	} else if len(parents) != 1 {
		t.Fatal("[role-a] should have one parent")
	}

	assert(t, rbac.Remove("role-a"))
	if _, ok := rbac.roles["role-a"]; ok {
		t.Fatal("Role removing failed")
	}
	if err := rbac.Remove("not-exist"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}

	if r, parents, err := rbac.GetRole("role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	} else if r != nil {
		t.Fatal("The instance of role should be a nil")
	} else if parents != nil {
		t.Fatal("The slice of parents should be a nil")
	}
}

func TestRbacParents(t *testing.T) {
	rbac := New()

	assert(t, rbac.Add(rB))
	assert(t, rbac.Add(rC))

	assert(t, rbac.SetParent("role-c", "role-b"))
	if _, ok := rbac.parents["role-c"]["role-b"]; !ok {
		t.Fatal("Parent binding failed")
	}

	assert(t, rbac.RemoveParent("role-c", "role-b"))
	if _, ok := rbac.parents["role-c"]["role-b"]; ok {
		t.Fatal("Parent unbinding failed")
	}

	if err := rbac.RemoveParent("role-a", "role-b"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.RemoveParent("role-b", "role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}

	if err := rbac.SetParent("role-a", "role-b"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.SetParent("role-c", "role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.SetParents("role-a", []string{"role-b"}); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.SetParents("role-c", []string{"role-a", "role-sa"}); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}

	assert(t, rbac.SetParents("role-c", []string{"role-b"}))
	if _, ok := rbac.parents["role-c"]["role-b"]; !ok {
		t.Fatal("Parent binding failed")
	}
	if parents, err := rbac.GetParents("role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	} else if len(parents) != 0 {
		t.Fatal("[role-a] should not have any parent")
	}
	if parents, err := rbac.GetParents("role-b"); err != nil {
		t.Fatal(err)
	} else if len(parents) != 0 {
		t.Fatal("[role-b] should not have any parent")
	}
	if parents, err := rbac.GetParents("role-c"); err != nil {
		t.Fatal(err)
	} else if len(parents) != 1 {
		t.Fatal("[role-c] should have one parent")
	}
}

func TestRbacPermission(t *testing.T) {
	rbac := New()

	assert(t, rbac.Add(rB))
	assert(t, rbac.Add(rC))
	assert(t, rbac.SetParents("role-c", []string{"role-b"}))

	if !rbac.IsGranted("role-c", pC, nil) {
		t.Fatalf("role-c should have %s", pC)
	}
	if rbac.IsGranted("role-c", pC, func(*RBAC, string, Permission) bool { return false }) {
		t.Fatal("Assertion don't work")
	}
	if !rbac.IsGranted("role-c", pB, nil) {
		t.Fatalf("role-c should have %s which inherits from role-b", pB)
	}

	assert(t, rbac.RemoveParent("role-c", "role-b"))
	if rbac.IsGranted("role-c", pB, nil) {
		t.Fatalf("role-c should not have %s because of the unbinding with role-b", pB)
	}

	if rbac.IsGranted("role-a", nil, nil) {
		t.Fatal("role-a should not have nil permission")
	}
}

func TestRbacPermissions(t *testing.T) {
	rbac := New()

	assert(t, rbac.Add(rA))
	assert(t, rbac.Add(rB))
	assert(t, rbac.Add(rC))

	r1 := NewRole("role-1")
	r2 := NewRole("role-2")
	r3 := NewRole("role-3")
	r4 := NewRole("role-4")
	r5 := NewRole("role-5")
	pD := NewPermission("permission-d")

	r1.Assign(pD)
	r2.Assign(pC)
	r3.Assign(pB).Assign(pC)
	r5.Assign(pA)
	r5.Assign(NewPermission(`nothing`))

	assert(t, rbac.Add(r1))
	assert(t, rbac.Add(r2))
	assert(t, rbac.Add(r3))
	assert(t, rbac.Add(r4))
	assert(t, rbac.Add(r5))

	assert(t, rbac.SetParent("role-2", "role-1"))
	assert(t, rbac.SetParent("role-3", "role-2"))
	assert(t, rbac.SetParent("role-5", "role-3"))

	/*
		assert(t, rbac.SetParent("role-c", "role-a"))

		if err := InheritanceCircle(rbac); err != nil {
			t.Fatal(err)
		}
	*/

	var permList Permissions

	for i := 1; i <= 5; i++ {
		permList = rbac.Permissions("role-" + strconv.Itoa(i))

		if i == 4 {
			if len(permList) != 0 {
				t.Errorf(`Error in %s`, "role-"+strconv.Itoa(i))
			}

			continue
		}

		if i != len(permList) {
			t.Errorf(`Error in %s`, "role-"+strconv.Itoa(i))
		}

	}
}

func BenchmarkRBAC_IsGranted(b *testing.B) {
	rbac := New()
	rA.Assign(pA)
	rB.Assign(pB)
	rC.Assign(pC)
	rbac.Add(rA)
	rbac.Add(rB)
	rbac.Add(rC)
	for i := 0; i < b.N; i++ {
		rbac.IsGranted("role-a", pA, nil)
	}
}

func BenchmarkRbacNotGranted(b *testing.B) {
	rbac := New()
	rA.Assign(pA)
	rB.Assign(pB)
	rC.Assign(pC)
	rbac.Add(rA)
	rbac.Add(rB)
	rbac.Add(rC)
	for i := 0; i < b.N; i++ {
		rbac.IsGranted("role-a", pB, nil)
	}
}

func TestRbac(t *testing.T) {
	rbac := New()

	//roleAuthor := NewRole("author")
	roleEditor := NewRole("editor")
	rolePhoto := NewRole("photographer")
	roleModerator := NewRole("moderator")
	roleAdmin := NewRole("admin")

	pTextEdit := NewPermission("text-edit")
	pTextAdd := NewPermission("text-add")
	pTextRemove := NewPermission("text-remove")

	//pTextOwnEdit := NewPermission("text-own-edit")
	//pTextOwnDelete := NewPermission("text-own-delete")

	//pEdit := NewPermission("edit")

	pPhotoAdd := NewPermission("photo-add")
	pPhotoEdit := NewPermission("photo-edit")
	pPhotoInsert := NewPermission("photo-insert")
	pPhotoDelete := NewPermission("photo-delete")

	pRoot := NewPermission("root")

	roleEditor.
		Assign(pTextEdit).
		Assign(pTextAdd).
		Assign(pPhotoInsert)

	roleModerator.
		Assign(pPhotoDelete).
		Assign(pTextRemove)

	//roleAuthor.
	//	Assign(pTextOwnEdit).
	//	Assign(pTextOwnDelete)

	rolePhoto.
		Assign(pPhotoAdd).
		Assign(pPhotoEdit)

	roleAdmin.
		Assign(pRoot)

	rbac.Add(roleAdmin)
	rbac.Add(roleModerator)
	rbac.Add(roleEditor)
	rbac.Add(rolePhoto)

	rbac.SetParents("moderator", []string{"photographer", "editor"})
	rbac.SetParents("admin", []string{"moderator"})

	if rbac.IsGranted("admin", pTextAdd, nil) &&
		rbac.IsGranted("admin", pTextRemove, nil) &&
		rbac.IsGranted("admin", pTextEdit, nil) &&
		rbac.IsGranted("admin", pPhotoAdd, nil) &&
		rbac.IsGranted("admin", pPhotoDelete, nil) &&
		rbac.IsGranted("admin", pPhotoEdit, nil) &&
		rbac.IsGranted("admin", pPhotoInsert, nil) &&
		rbac.IsGranted("admin", pRoot, nil) {
		fmt.Println("The role 'Admin` has been granted on roles: moderator, editor, photographer and permissions: root.")
	}

	if rbac.IsGranted("moderator", pTextRemove, nil) &&
		rbac.IsGranted("moderator", pPhotoInsert, nil) &&
		rbac.IsGranted("moderator", pPhotoDelete, nil) &&
		!rbac.IsGranted("moderator", pRoot, nil) {
		fmt.Println("The MODERATOR has been granted editor, photographer and permissions: photo-delete and text-delete.")
	}

	// Output:
	// The role 'Admin` has been granted on roles: moderator, editor, photographer and permissions: root.
	// The MODERATOR has been granted editor, photographer and permissions: photo-delete and text-delete.
}
