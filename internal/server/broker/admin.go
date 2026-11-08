package broker

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// Setup describes what migrate prepares for the server.
type Setup struct {
	Topic       string
	Group       string
	Partitions  int32
	Replication int16
	Retention   time.Duration
	// User and Password are the server's own account. It may read and write the
	// topic and use the group, and nothing else.
	User     string
	Password string
}

const scramIterations = 4096

func adminClient(admin Settings) (*kadm.Client, error) {
	options, err := admin.options()
	if err != nil {
		return nil, err
	}
	client, err := kgo.NewClient(options...)
	if err != nil {
		return nil, fmt.Errorf("create broker admin: %w", err)
	}
	return kadm.NewClient(client), nil
}

// Ensure creates the topic, the server's account and its ACLs, or brings them
// up to date. Running it again changes nothing that is already right.
func Ensure(ctx context.Context, admin Settings, setup Setup) error {
	if setup.Replication < 1 || setup.Partitions < 1 || setup.Retention <= 0 {
		return errors.New("partitions, replication and retention must be positive")
	}
	client, err := adminClient(admin)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := ensureTopic(ctx, client, setup); err != nil {
		return err
	}
	if err := ensureAccount(ctx, client, setup); err != nil {
		return err
	}
	return grant(ctx, client, setup)
}

func ensureTopic(ctx context.Context, client *kadm.Client, setup Setup) error {
	configs := map[string]*string{
		"retention.ms":        new(strconv.FormatInt(setup.Retention.Milliseconds(), 10)),
		"cleanup.policy":      new("delete"),
		"min.insync.replicas": new(strconv.Itoa(int(min(setup.Replication, 2)))),
	}
	topics, err := client.ListTopics(ctx, setup.Topic)
	if err != nil {
		return fmt.Errorf("list topics: %w", err)
	}
	if !topics.Has(setup.Topic) {
		created, err := client.CreateTopic(ctx, setup.Partitions, setup.Replication, configs, setup.Topic)
		if err != nil || created.Err != nil {
			return fmt.Errorf("create topic: %w", errors.Join(err, created.Err))
		}
		return nil
	}
	alterations := make([]kadm.AlterConfig, 0, len(configs))
	for name, value := range configs {
		alterations = append(alterations, kadm.AlterConfig{Op: kadm.SetConfig, Name: name, Value: value})
	}
	altered, err := client.AlterTopicConfigs(ctx, alterations, setup.Topic)
	if err == nil {
		_, err = altered.On(setup.Topic, nil)
	}
	if err != nil {
		return fmt.Errorf("update topic: %w", err)
	}
	return nil
}

func ensureAccount(ctx context.Context, client *kadm.Client, setup Setup) error {
	scram, err := client.AlterUserSCRAMs(ctx, nil, []kadm.UpsertSCRAM{{
		User: setup.User, Mechanism: kadm.ScramSha256, Iterations: scramIterations, Password: setup.Password,
	}})
	if err == nil {
		err = scram.Error()
	}
	if err != nil {
		return fmt.Errorf("set server account: %w", err)
	}
	return nil
}

func grant(ctx context.Context, client *kadm.Client, setup Setup) error {
	for _, acl := range serverACLs(setup) {
		results, err := client.CreateACLs(ctx, acl)
		if err != nil {
			return fmt.Errorf("grant server account: %w", err)
		}
		for _, result := range results {
			if result.Err != nil {
				return fmt.Errorf("grant server account: %w", result.Err)
			}
		}
	}
	return nil
}

// serverACLs is all the server may do: write and read its topic, use its group.
func serverACLs(setup Setup) []*kadm.ACLBuilder {
	principal := "User:" + setup.User
	return []*kadm.ACLBuilder{
		kadm.NewACLs().Allow(principal).AllowHosts().Topics(setup.Topic).ResourcePatternType(kadm.ACLPatternLiteral).
			Operations(kmsg.ACLOperationRead, kmsg.ACLOperationWrite, kmsg.ACLOperationDescribe),
		kadm.NewACLs().Allow(principal).AllowHosts().Groups(setup.Group).ResourcePatternType(kadm.ACLPatternLiteral).
			Operations(kmsg.ACLOperationRead, kmsg.ACLOperationDescribe),
	}
}

// Remove deletes a topic and the server's ACLs on it. Tests use it to clean up.
func Remove(ctx context.Context, admin Settings, setup Setup) error {
	client, err := adminClient(admin)
	if err != nil {
		return err
	}
	defer client.Close()
	var errs []error
	for _, acl := range serverACLs(setup) {
		_, err := client.DeleteACLs(ctx, acl)
		errs = append(errs, err)
	}
	_, err = client.DeleteTopics(ctx, setup.Topic)
	return errors.Join(append(errs, err)...)
}
