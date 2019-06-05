package gorbac

import (
	"errors"
	"sync"
)

var (
	// ErrRoleNotExist occurred if a role cann't be found
	ErrRoleNotExist = errors.New("role does not exist")
	// ErrRoleExist occurred if a role shouldn't be found
	ErrRoleExist = errors.New("role has already existed")
	empty        = struct{}{}
)

// AssertionFunc supplies more fine-grained permission controls.
type AssertionFunc func(*RBAC, string, Permission) bool

// RBAC object, in most cases it should be used as a singleton.
type RBAC struct {
	mutex   sync.RWMutex
	roles   Roles
	parents map[string]map[string]struct{}
}

// New returns a RBAC structure.
// The default role structure will be used.
func New() *RBAC {
	return &RBAC{
		roles:   make(Roles),
		parents: make(map[string]map[string]struct{}),
	}
}

// SetParents bind `parents` to the role `id`.
// If the role or any of parents is not existing,
// an error will be returned.
func (rbac *RBAC) SetParents(id string, parents []string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	for _, parent := range parents {
		if _, ok := rbac.roles[parent]; !ok {
			return ErrRoleNotExist
		}
	}
	if _, ok := rbac.parents[id]; !ok {
		rbac.parents[id] = make(map[string]struct{})
	}
	for _, parent := range parents {
		rbac.parents[id][parent] = empty
	}
	return nil
}

// GetParents return `parents` of the role `id`.
// If the role is not existing, an error will be returned.
// Or the role doesn't have any parents,
// a nil slice will be returned.
func (rbac *RBAC) GetParents(id string) ([]string, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return nil, ErrRoleNotExist
	}
	ids, ok := rbac.parents[id]
	if !ok {
		return nil, nil
	}
	var parents []string
	for parent := range ids {
		parents = append(parents, parent)
	}
	return parents, nil
}

// SetParent bind the `parent` to the role `id`.
// If the role or the parent is not existing,
// an error will be returned.
func (rbac *RBAC) SetParent(id string, parent string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.roles[parent]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.parents[id]; !ok {
		rbac.parents[id] = make(map[string]struct{})
	}
	var empty struct{}
	rbac.parents[id][parent] = empty
	return nil
}

// RemoveParent unbind the `parent` with the role `id`.
// If the role or the parent is not existing,
// an error will be returned.
func (rbac *RBAC) RemoveParent(id string, parent string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.roles[parent]; !ok {
		return ErrRoleNotExist
	}

	delete(rbac.parents[id], parent)

	return nil
}

// Add a role `r`.
func (rbac *RBAC) Add(r Role) (err error) {
	rbac.mutex.Lock()
	if _, ok := rbac.roles[r.ID()]; !ok {
		rbac.roles[r.ID()] = r
	} else {
		err = ErrRoleExist
	}
	rbac.mutex.Unlock()
	return
}

// Remove the role by `id`.
func (rbac *RBAC) Remove(id string) (err error) {
	rbac.mutex.Lock()
	if _, ok := rbac.roles[id]; ok {
		delete(rbac.roles, id)
		for rid, parents := range rbac.parents {
			if rid == id {
				delete(rbac.parents, rid)
				continue
			}
			for parent := range parents {
				if parent == id {
					delete(rbac.parents[rid], id)
					break
				}
			}
		}
	} else {
		err = ErrRoleNotExist
	}
	rbac.mutex.Unlock()
	return
}

// GetRole by `id` and a slice of its parents id.
func (rbac *RBAC) GetRole(id string) (r Role, parents []string, err error) {
	rbac.mutex.RLock()
	var ok bool
	if r, ok = rbac.roles[id]; ok {
		for parent := range rbac.parents[id] {
			parents = append(parents, parent)
		}
	} else {
		err = ErrRoleNotExist
	}
	rbac.mutex.RUnlock()
	return
}

// GetRoles returns role list
func (rbac *RBAC) GetRoles() []*Role {
	rbac.mutex.RLock()

	result := make([]*Role, 0, len(rbac.roles))
	for _, r := range rbac.roles {
		result = append(result, &r)
	}

	rbac.mutex.RUnlock()
	return result
}

// Permissions get list of all permissions
func (rbac *RBAC) Permissions(id string) Permissions {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	list := make(Permissions)

	if role, ok := rbac.roles[id]; ok {
		for _, p := range role.Permissions() {
			list[p.ID()] = p
		}

		if parents, ok := rbac.parents[id]; ok {
			for pID := range parents {
				if _, ok := rbac.roles[pID]; ok {
					for _, p := range rbac.Permissions(pID) {
						list[p.ID()] = p
					}
				}
			}
		}
	}
	return list
}

// IsGranted tests if the role `id` has Permission `p` with the condition `assert`.
func (rbac *RBAC) IsGranted(id string, p Permission, assert AssertionFunc) (rslt bool) {
	rbac.mutex.RLock()
	rslt = rbac.isGranted(id, p, assert)
	rbac.mutex.RUnlock()
	return
}

func (rbac *RBAC) isGranted(id string, p Permission, assert AssertionFunc) bool {
	if assert != nil && !assert(rbac, id, p) {
		return false
	}
	return rbac.recursionCheck(id, p)
}

func (rbac *RBAC) recursionCheck(id string, p Permission) bool {
	if role, ok := rbac.roles[id]; ok {
		if role.Permit(p) {
			return true
		}
		if parents, ok := rbac.parents[id]; ok {
			for pID := range parents {
				if _, ok := rbac.roles[pID]; ok {
					if rbac.recursionCheck(pID, p) {
						return true
					}
				}
			}
		}
	}
	return false
}
