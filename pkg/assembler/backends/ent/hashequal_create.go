// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
)

// HashEqualCreate is the builder for creating a HashEqual entity.
type HashEqualCreate struct {
	config
	mutation *HashEqualMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetArtID sets the "art_id" field.
func (hec *HashEqualCreate) SetArtID(u uuid.UUID) *HashEqualCreate {
	hec.mutation.SetArtID(u)
	return hec
}

// SetEqualArtID sets the "equal_art_id" field.
func (hec *HashEqualCreate) SetEqualArtID(u uuid.UUID) *HashEqualCreate {
	hec.mutation.SetEqualArtID(u)
	return hec
}

// SetOrigin sets the "origin" field.
func (hec *HashEqualCreate) SetOrigin(s string) *HashEqualCreate {
	hec.mutation.SetOrigin(s)
	return hec
}

// SetCollector sets the "collector" field.
func (hec *HashEqualCreate) SetCollector(s string) *HashEqualCreate {
	hec.mutation.SetCollector(s)
	return hec
}

// SetJustification sets the "justification" field.
func (hec *HashEqualCreate) SetJustification(s string) *HashEqualCreate {
	hec.mutation.SetJustification(s)
	return hec
}

// SetDocumentRef sets the "document_ref" field.
func (hec *HashEqualCreate) SetDocumentRef(s string) *HashEqualCreate {
	hec.mutation.SetDocumentRef(s)
	return hec
}

// SetArtifactsHash sets the "artifacts_hash" field.
func (hec *HashEqualCreate) SetArtifactsHash(s string) *HashEqualCreate {
	hec.mutation.SetArtifactsHash(s)
	return hec
}

// SetID sets the "id" field.
func (hec *HashEqualCreate) SetID(u uuid.UUID) *HashEqualCreate {
	hec.mutation.SetID(u)
	return hec
}

// SetNillableID sets the "id" field if the given value is not nil.
func (hec *HashEqualCreate) SetNillableID(u *uuid.UUID) *HashEqualCreate {
	if u != nil {
		hec.SetID(*u)
	}
	return hec
}

// SetArtifactAID sets the "artifact_a" edge to the Artifact entity by ID.
func (hec *HashEqualCreate) SetArtifactAID(id uuid.UUID) *HashEqualCreate {
	hec.mutation.SetArtifactAID(id)
	return hec
}

// SetArtifactA sets the "artifact_a" edge to the Artifact entity.
func (hec *HashEqualCreate) SetArtifactA(a *Artifact) *HashEqualCreate {
	return hec.SetArtifactAID(a.ID)
}

// SetArtifactBID sets the "artifact_b" edge to the Artifact entity by ID.
func (hec *HashEqualCreate) SetArtifactBID(id uuid.UUID) *HashEqualCreate {
	hec.mutation.SetArtifactBID(id)
	return hec
}

// SetArtifactB sets the "artifact_b" edge to the Artifact entity.
func (hec *HashEqualCreate) SetArtifactB(a *Artifact) *HashEqualCreate {
	return hec.SetArtifactBID(a.ID)
}

// Mutation returns the HashEqualMutation object of the builder.
func (hec *HashEqualCreate) Mutation() *HashEqualMutation {
	return hec.mutation
}

// Save creates the HashEqual in the database.
func (hec *HashEqualCreate) Save(ctx context.Context) (*HashEqual, error) {
	hec.defaults()
	return withHooks(ctx, hec.sqlSave, hec.mutation, hec.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (hec *HashEqualCreate) SaveX(ctx context.Context) *HashEqual {
	v, err := hec.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (hec *HashEqualCreate) Exec(ctx context.Context) error {
	_, err := hec.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (hec *HashEqualCreate) ExecX(ctx context.Context) {
	if err := hec.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (hec *HashEqualCreate) defaults() {
	if _, ok := hec.mutation.ID(); !ok {
		v := hashequal.DefaultID()
		hec.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (hec *HashEqualCreate) check() error {
	if _, ok := hec.mutation.ArtID(); !ok {
		return &ValidationError{Name: "art_id", err: errors.New(`ent: missing required field "HashEqual.art_id"`)}
	}
	if _, ok := hec.mutation.EqualArtID(); !ok {
		return &ValidationError{Name: "equal_art_id", err: errors.New(`ent: missing required field "HashEqual.equal_art_id"`)}
	}
	if _, ok := hec.mutation.Origin(); !ok {
		return &ValidationError{Name: "origin", err: errors.New(`ent: missing required field "HashEqual.origin"`)}
	}
	if _, ok := hec.mutation.Collector(); !ok {
		return &ValidationError{Name: "collector", err: errors.New(`ent: missing required field "HashEqual.collector"`)}
	}
	if _, ok := hec.mutation.Justification(); !ok {
		return &ValidationError{Name: "justification", err: errors.New(`ent: missing required field "HashEqual.justification"`)}
	}
	if _, ok := hec.mutation.DocumentRef(); !ok {
		return &ValidationError{Name: "document_ref", err: errors.New(`ent: missing required field "HashEqual.document_ref"`)}
	}
	if _, ok := hec.mutation.ArtifactsHash(); !ok {
		return &ValidationError{Name: "artifacts_hash", err: errors.New(`ent: missing required field "HashEqual.artifacts_hash"`)}
	}
	if len(hec.mutation.ArtifactAIDs()) == 0 {
		return &ValidationError{Name: "artifact_a", err: errors.New(`ent: missing required edge "HashEqual.artifact_a"`)}
	}
	if len(hec.mutation.ArtifactBIDs()) == 0 {
		return &ValidationError{Name: "artifact_b", err: errors.New(`ent: missing required edge "HashEqual.artifact_b"`)}
	}
	return nil
}

func (hec *HashEqualCreate) sqlSave(ctx context.Context) (*HashEqual, error) {
	if err := hec.check(); err != nil {
		return nil, err
	}
	_node, _spec := hec.createSpec()
	if err := sqlgraph.CreateNode(ctx, hec.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	hec.mutation.id = &_node.ID
	hec.mutation.done = true
	return _node, nil
}

func (hec *HashEqualCreate) createSpec() (*HashEqual, *sqlgraph.CreateSpec) {
	var (
		_node = &HashEqual{config: hec.config}
		_spec = sqlgraph.NewCreateSpec(hashequal.Table, sqlgraph.NewFieldSpec(hashequal.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = hec.conflict
	if id, ok := hec.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := hec.mutation.Origin(); ok {
		_spec.SetField(hashequal.FieldOrigin, field.TypeString, value)
		_node.Origin = value
	}
	if value, ok := hec.mutation.Collector(); ok {
		_spec.SetField(hashequal.FieldCollector, field.TypeString, value)
		_node.Collector = value
	}
	if value, ok := hec.mutation.Justification(); ok {
		_spec.SetField(hashequal.FieldJustification, field.TypeString, value)
		_node.Justification = value
	}
	if value, ok := hec.mutation.DocumentRef(); ok {
		_spec.SetField(hashequal.FieldDocumentRef, field.TypeString, value)
		_node.DocumentRef = value
	}
	if value, ok := hec.mutation.ArtifactsHash(); ok {
		_spec.SetField(hashequal.FieldArtifactsHash, field.TypeString, value)
		_node.ArtifactsHash = value
	}
	if nodes := hec.mutation.ArtifactAIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hashequal.ArtifactATable,
			Columns: []string{hashequal.ArtifactAColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.ArtID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := hec.mutation.ArtifactBIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hashequal.ArtifactBTable,
			Columns: []string{hashequal.ArtifactBColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.EqualArtID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.HashEqual.Create().
//		SetArtID(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.HashEqualUpsert) {
//			SetArtID(v+v).
//		}).
//		Exec(ctx)
func (hec *HashEqualCreate) OnConflict(opts ...sql.ConflictOption) *HashEqualUpsertOne {
	hec.conflict = opts
	return &HashEqualUpsertOne{
		create: hec,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.HashEqual.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (hec *HashEqualCreate) OnConflictColumns(columns ...string) *HashEqualUpsertOne {
	hec.conflict = append(hec.conflict, sql.ConflictColumns(columns...))
	return &HashEqualUpsertOne{
		create: hec,
	}
}

type (
	// HashEqualUpsertOne is the builder for "upsert"-ing
	//  one HashEqual node.
	HashEqualUpsertOne struct {
		create *HashEqualCreate
	}

	// HashEqualUpsert is the "OnConflict" setter.
	HashEqualUpsert struct {
		*sql.UpdateSet
	}
)

// SetArtID sets the "art_id" field.
func (u *HashEqualUpsert) SetArtID(v uuid.UUID) *HashEqualUpsert {
	u.Set(hashequal.FieldArtID, v)
	return u
}

// UpdateArtID sets the "art_id" field to the value that was provided on create.
func (u *HashEqualUpsert) UpdateArtID() *HashEqualUpsert {
	u.SetExcluded(hashequal.FieldArtID)
	return u
}

// SetEqualArtID sets the "equal_art_id" field.
func (u *HashEqualUpsert) SetEqualArtID(v uuid.UUID) *HashEqualUpsert {
	u.Set(hashequal.FieldEqualArtID, v)
	return u
}

// UpdateEqualArtID sets the "equal_art_id" field to the value that was provided on create.
func (u *HashEqualUpsert) UpdateEqualArtID() *HashEqualUpsert {
	u.SetExcluded(hashequal.FieldEqualArtID)
	return u
}

// SetOrigin sets the "origin" field.
func (u *HashEqualUpsert) SetOrigin(v string) *HashEqualUpsert {
	u.Set(hashequal.FieldOrigin, v)
	return u
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *HashEqualUpsert) UpdateOrigin() *HashEqualUpsert {
	u.SetExcluded(hashequal.FieldOrigin)
	return u
}

// SetCollector sets the "collector" field.
func (u *HashEqualUpsert) SetCollector(v string) *HashEqualUpsert {
	u.Set(hashequal.FieldCollector, v)
	return u
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *HashEqualUpsert) UpdateCollector() *HashEqualUpsert {
	u.SetExcluded(hashequal.FieldCollector)
	return u
}

// SetJustification sets the "justification" field.
func (u *HashEqualUpsert) SetJustification(v string) *HashEqualUpsert {
	u.Set(hashequal.FieldJustification, v)
	return u
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *HashEqualUpsert) UpdateJustification() *HashEqualUpsert {
	u.SetExcluded(hashequal.FieldJustification)
	return u
}

// SetDocumentRef sets the "document_ref" field.
func (u *HashEqualUpsert) SetDocumentRef(v string) *HashEqualUpsert {
	u.Set(hashequal.FieldDocumentRef, v)
	return u
}

// UpdateDocumentRef sets the "document_ref" field to the value that was provided on create.
func (u *HashEqualUpsert) UpdateDocumentRef() *HashEqualUpsert {
	u.SetExcluded(hashequal.FieldDocumentRef)
	return u
}

// SetArtifactsHash sets the "artifacts_hash" field.
func (u *HashEqualUpsert) SetArtifactsHash(v string) *HashEqualUpsert {
	u.Set(hashequal.FieldArtifactsHash, v)
	return u
}

// UpdateArtifactsHash sets the "artifacts_hash" field to the value that was provided on create.
func (u *HashEqualUpsert) UpdateArtifactsHash() *HashEqualUpsert {
	u.SetExcluded(hashequal.FieldArtifactsHash)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.HashEqual.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(hashequal.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *HashEqualUpsertOne) UpdateNewValues() *HashEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(hashequal.FieldID)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.HashEqual.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *HashEqualUpsertOne) Ignore() *HashEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *HashEqualUpsertOne) DoNothing() *HashEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the HashEqualCreate.OnConflict
// documentation for more info.
func (u *HashEqualUpsertOne) Update(set func(*HashEqualUpsert)) *HashEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&HashEqualUpsert{UpdateSet: update})
	}))
	return u
}

// SetArtID sets the "art_id" field.
func (u *HashEqualUpsertOne) SetArtID(v uuid.UUID) *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetArtID(v)
	})
}

// UpdateArtID sets the "art_id" field to the value that was provided on create.
func (u *HashEqualUpsertOne) UpdateArtID() *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateArtID()
	})
}

// SetEqualArtID sets the "equal_art_id" field.
func (u *HashEqualUpsertOne) SetEqualArtID(v uuid.UUID) *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetEqualArtID(v)
	})
}

// UpdateEqualArtID sets the "equal_art_id" field to the value that was provided on create.
func (u *HashEqualUpsertOne) UpdateEqualArtID() *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateEqualArtID()
	})
}

// SetOrigin sets the "origin" field.
func (u *HashEqualUpsertOne) SetOrigin(v string) *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *HashEqualUpsertOne) UpdateOrigin() *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *HashEqualUpsertOne) SetCollector(v string) *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *HashEqualUpsertOne) UpdateCollector() *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateCollector()
	})
}

// SetJustification sets the "justification" field.
func (u *HashEqualUpsertOne) SetJustification(v string) *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *HashEqualUpsertOne) UpdateJustification() *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateJustification()
	})
}

// SetDocumentRef sets the "document_ref" field.
func (u *HashEqualUpsertOne) SetDocumentRef(v string) *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetDocumentRef(v)
	})
}

// UpdateDocumentRef sets the "document_ref" field to the value that was provided on create.
func (u *HashEqualUpsertOne) UpdateDocumentRef() *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateDocumentRef()
	})
}

// SetArtifactsHash sets the "artifacts_hash" field.
func (u *HashEqualUpsertOne) SetArtifactsHash(v string) *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetArtifactsHash(v)
	})
}

// UpdateArtifactsHash sets the "artifacts_hash" field to the value that was provided on create.
func (u *HashEqualUpsertOne) UpdateArtifactsHash() *HashEqualUpsertOne {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateArtifactsHash()
	})
}

// Exec executes the query.
func (u *HashEqualUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for HashEqualCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *HashEqualUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *HashEqualUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: HashEqualUpsertOne.ID is not supported by MySQL driver. Use HashEqualUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *HashEqualUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// HashEqualCreateBulk is the builder for creating many HashEqual entities in bulk.
type HashEqualCreateBulk struct {
	config
	err      error
	builders []*HashEqualCreate
	conflict []sql.ConflictOption
}

// Save creates the HashEqual entities in the database.
func (hecb *HashEqualCreateBulk) Save(ctx context.Context) ([]*HashEqual, error) {
	if hecb.err != nil {
		return nil, hecb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(hecb.builders))
	nodes := make([]*HashEqual, len(hecb.builders))
	mutators := make([]Mutator, len(hecb.builders))
	for i := range hecb.builders {
		func(i int, root context.Context) {
			builder := hecb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*HashEqualMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, hecb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = hecb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, hecb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, hecb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (hecb *HashEqualCreateBulk) SaveX(ctx context.Context) []*HashEqual {
	v, err := hecb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (hecb *HashEqualCreateBulk) Exec(ctx context.Context) error {
	_, err := hecb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (hecb *HashEqualCreateBulk) ExecX(ctx context.Context) {
	if err := hecb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.HashEqual.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.HashEqualUpsert) {
//			SetArtID(v+v).
//		}).
//		Exec(ctx)
func (hecb *HashEqualCreateBulk) OnConflict(opts ...sql.ConflictOption) *HashEqualUpsertBulk {
	hecb.conflict = opts
	return &HashEqualUpsertBulk{
		create: hecb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.HashEqual.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (hecb *HashEqualCreateBulk) OnConflictColumns(columns ...string) *HashEqualUpsertBulk {
	hecb.conflict = append(hecb.conflict, sql.ConflictColumns(columns...))
	return &HashEqualUpsertBulk{
		create: hecb,
	}
}

// HashEqualUpsertBulk is the builder for "upsert"-ing
// a bulk of HashEqual nodes.
type HashEqualUpsertBulk struct {
	create *HashEqualCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.HashEqual.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(hashequal.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *HashEqualUpsertBulk) UpdateNewValues() *HashEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(hashequal.FieldID)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.HashEqual.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *HashEqualUpsertBulk) Ignore() *HashEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *HashEqualUpsertBulk) DoNothing() *HashEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the HashEqualCreateBulk.OnConflict
// documentation for more info.
func (u *HashEqualUpsertBulk) Update(set func(*HashEqualUpsert)) *HashEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&HashEqualUpsert{UpdateSet: update})
	}))
	return u
}

// SetArtID sets the "art_id" field.
func (u *HashEqualUpsertBulk) SetArtID(v uuid.UUID) *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetArtID(v)
	})
}

// UpdateArtID sets the "art_id" field to the value that was provided on create.
func (u *HashEqualUpsertBulk) UpdateArtID() *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateArtID()
	})
}

// SetEqualArtID sets the "equal_art_id" field.
func (u *HashEqualUpsertBulk) SetEqualArtID(v uuid.UUID) *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetEqualArtID(v)
	})
}

// UpdateEqualArtID sets the "equal_art_id" field to the value that was provided on create.
func (u *HashEqualUpsertBulk) UpdateEqualArtID() *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateEqualArtID()
	})
}

// SetOrigin sets the "origin" field.
func (u *HashEqualUpsertBulk) SetOrigin(v string) *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *HashEqualUpsertBulk) UpdateOrigin() *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *HashEqualUpsertBulk) SetCollector(v string) *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *HashEqualUpsertBulk) UpdateCollector() *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateCollector()
	})
}

// SetJustification sets the "justification" field.
func (u *HashEqualUpsertBulk) SetJustification(v string) *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *HashEqualUpsertBulk) UpdateJustification() *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateJustification()
	})
}

// SetDocumentRef sets the "document_ref" field.
func (u *HashEqualUpsertBulk) SetDocumentRef(v string) *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetDocumentRef(v)
	})
}

// UpdateDocumentRef sets the "document_ref" field to the value that was provided on create.
func (u *HashEqualUpsertBulk) UpdateDocumentRef() *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateDocumentRef()
	})
}

// SetArtifactsHash sets the "artifacts_hash" field.
func (u *HashEqualUpsertBulk) SetArtifactsHash(v string) *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.SetArtifactsHash(v)
	})
}

// UpdateArtifactsHash sets the "artifacts_hash" field to the value that was provided on create.
func (u *HashEqualUpsertBulk) UpdateArtifactsHash() *HashEqualUpsertBulk {
	return u.Update(func(s *HashEqualUpsert) {
		s.UpdateArtifactsHash()
	})
}

// Exec executes the query.
func (u *HashEqualUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the HashEqualCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for HashEqualCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *HashEqualUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
