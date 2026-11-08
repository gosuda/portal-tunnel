package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestCommentsPersistAndStayWithTheirAppIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	store, err := NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	comments, err := store.AddComment("app-owner-a", "  First comment\nwith another line.  ", "", "author")
	if err != nil || len(comments) != 1 {
		t.Fatalf("add comment: %v, %v", comments, err)
	}
	if comments[0].Text != "First comment\nwith another line." || comments[0].ID == "" || comments[0].CreatedAt.IsZero() {
		t.Fatalf("invalid comment: %+v", comments[0])
	}
	store, err = NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.ListComments("app-owner-a", "", "author"); len(got) != 1 || got[0] != comments[0] {
		t.Fatalf("comment did not survive restart: %v", got)
	}
	if got := store.ListComments("app-owner-b", "", "author"); len(got) != 0 {
		t.Fatalf("another owner inherited comments: %v", got)
	}
	if _, err := store.DeleteComment("app-owner-a", comments[0].ID, "", "stranger"); !errors.Is(err, ErrCommentNotFound) {
		t.Fatalf("stranger was able to delete comment: %v", err)
	}
	if _, err := store.DeleteComment("app-owner-a", comments[0].ID, "", "author"); err != nil {
		t.Fatal(err)
	}
	store, err = NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.ListComments("app-owner-a", "", "author")) != 0 {
		t.Fatal("deleted comment reappeared after restart")
	}
	if _, err := store.DeleteComment("app-owner-a", comments[0].ID, "", "author"); !errors.Is(err, ErrCommentNotFound) {
		t.Fatalf("missing comment: %v", err)
	}
}

func TestCommentsRejectEmptyOversizeAndFullThreads(t *testing.T) {
	store, err := NewReputationStore(filepath.Join(t.TempDir(), "reputation.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"", " \n\t ", strings.Repeat("x", types.CommentMaxLength+1)} {
		if _, err := store.AddComment("app", text, "", "author"); !errors.Is(err, ErrCommentInvalid) {
			t.Fatalf("invalid text accepted: %v", err)
		}
	}
	for range commentsMaxPerApp {
		if _, err := store.AddComment("app", "A comment", "", "author"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AddComment("app", "One too many", "", "author"); !errors.Is(err, ErrCommentCapacity) {
		t.Fatalf("full thread accepted another comment: %v", err)
	}
	if len(store.ListComments("app", "", "author")) != commentsMaxPerApp {
		t.Fatal("capacity rejection changed the thread")
	}
}

func TestCommentsFailedWriteDoesNotPublishComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	store, err := NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the destination makes atomic replacement fail on all OSes.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddComment("app", "Not saved", "", "author"); err == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	if len(store.ListComments("app", "", "author")) != 0 {
		t.Fatal("failed write published a non-durable comment")
	}
}

func TestReputationImportsCombinedLegacyComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	store, err := NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const hostname, identity = "app.example.com", "id:app.example.com"
	source := netip.MustParseAddr("203.0.113.10")
	_, cookie, err := store.Vote(identity, "", VoteUp, "", source)
	if err != nil {
		t.Fatal(err)
	}
	// Existing installations have no comments field in reputation.json.
	if err := utils.WriteJSONFile(path, map[string]any{
		"voter_secret": store.state.VoterSecret,
		"identities":   store.state.Identities,
	}, 0o600); err != nil {
		t.Fatal(err)
	}
	comment := types.AppComment{ID: "old-comment", Text: "Existing comment", CreatedAt: time.Now().UTC(), Up: 99, ViewerVote: VoteUp, CanDelete: true}
	legacy := struct {
		Threads map[string][]types.AppComment `json:"threads"`
		Votes   map[string]map[string]string  `json:"votes"`
		Authors map[string]string             `json:"authors"`
	}{
		Threads: map[string][]types.AppComment{identity: {comment}},
		Votes:   map[string]map[string]string{comment.ID: {store.ViewerHashFor(cookie): VoteDown}},
		Authors: map[string]string{comment.ID: "author"},
	}
	if err := utils.WriteJSONFile(filepath.Join(filepath.Dir(path), "comments.json"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	comments := store.ListComments(identity, store.ViewerHashFor(cookie), "author")
	if len(comments) != 1 || comments[0].Text != comment.Text {
		t.Fatalf("legacy comment not imported: %+v", comments)
	}
	if comments[0].Down != 1 || comments[0].ViewerVote != VoteDown || !comments[0].CanDelete {
		t.Fatalf("legacy votes or deletion rights lost: %+v", comments[0])
	}
	if comments[0].Up != 0 {
		t.Fatalf("legacy response fields were treated as stored state: %+v", comments[0])
	}
	summary, minted, err := store.Vote(identity, comment.ID, VoteUp, cookie, source)
	if err != nil || minted != "" || summary.Up != 1 || summary.Down != 0 {
		t.Fatalf("shared voter cookie: %+v, cookie=%q, err=%v", summary, minted, err)
	}
	if _, _, err := store.Vote(identity, "", VoteDown, cookie, source); err != nil {
		t.Fatal(err)
	}
	store, err = NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	comments = store.ListComments(identity, store.ViewerHashFor(cookie), "author")
	if len(comments) != 1 || comments[0].ViewerVote != VoteUp {
		t.Fatalf("app vote overwrote comment state: %+v", comments)
	}
	if _, err := store.DeleteComment(identity, comment.ID, "", "author"); err != nil {
		t.Fatal(err)
	}
	store, err = NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.ListComments(identity, "", "author")) != 0 {
		t.Fatal("deleted comment was imported again from the old file")
	}
	row := store.Summaries(store.ViewerHashFor(cookie), testLeases(hostname))[0]
	if row.Down != 1 || row.ViewerVote != VoteDown || row.Total != 1 {
		t.Fatalf("comment mutation overwrote app vote or cookie identity: %+v", row)
	}
}

func TestReputationImportsThreadsOnlyLegacyComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	store, err := NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const hostname, identity = "app.example.com", "id:app.example.com"
	source := netip.MustParseAddr("203.0.113.10")
	_, cookie, err := store.Vote(identity, "", VoteUp, "", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := utils.WriteJSONFile(path, map[string]any{
		"voter_secret": store.state.VoterSecret,
		"identities":   store.state.Identities,
	}, 0o600); err != nil {
		t.Fatal(err)
	}
	comment := types.AppComment{ID: "old-comment", Text: "Existing comment", CreatedAt: time.Now().UTC(), Up: 99, ViewerVote: VoteUp, CanDelete: true}
	threads := map[string][]types.AppComment{identity: {comment}}
	if err := utils.WriteJSONFile(filepath.Join(filepath.Dir(path), "comments.json"), threads, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = NewReputationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	comments := store.ListComments(identity, store.ViewerHashFor(cookie), "author")
	if len(comments) != 1 || comments[0].Text != comment.Text {
		t.Fatalf("legacy comment not imported: %+v", comments)
	}
	if comments[0].Up != 0 || comments[0].ViewerVote != "" || comments[0].CanDelete {
		t.Fatalf("legacy response fields were treated as stored state: %+v", comments[0])
	}
	if _, err := store.DeleteComment(identity, comment.ID, "", "author"); !errors.Is(err, ErrCommentNotFound) {
		t.Fatalf("invented deletion rights for legacy comment: %v", err)
	}
}

func TestCommentsPersistOnlySourceData(t *testing.T) {
	store := newTestReputationStore(t)
	comments, err := store.AddComment("app", "A comment", "", "author")
	if err != nil {
		t.Fatal(err)
	}
	_, cookie, err := store.Vote("app", comments[0].ID, VoteUp, "", netip.MustParseAddr("203.0.113.10"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Comments struct {
			Threads map[string][]map[string]json.RawMessage `json:"threads"`
		} `json:"comments"`
	}
	if _, err := utils.ReadJSONFileIfExists(store.path, &persisted); err != nil {
		t.Fatal(err)
	}
	thread := persisted.Comments.Threads["app"]
	if len(thread) != 1 || len(thread[0]) != 3 || thread[0]["id"] == nil || thread[0]["text"] == nil || thread[0]["created_at"] == nil {
		t.Fatalf("persisted comment contains response fields or lost source data: %+v", thread)
	}
	reloaded, err := NewReputationStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	comments = reloaded.ListComments("app", reloaded.ViewerHashFor(cookie), "author")
	if len(comments) != 1 || comments[0].Up != 1 || comments[0].ViewerVote != VoteUp || !comments[0].CanDelete {
		t.Fatalf("response projection did not survive restart: %+v", comments)
	}
}
