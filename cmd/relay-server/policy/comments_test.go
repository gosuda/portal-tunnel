package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestCommentsPersistAndStayWithTheirAppIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "comments.json")
	store, err := NewCommentsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	comments, err := store.Add("app-owner-a", "  First comment\nwith another line.  ", "", "author")
	if err != nil || len(comments) != 1 {
		t.Fatalf("add comment: %v, %v", comments, err)
	}
	if comments[0].Text != "First comment\nwith another line." || comments[0].ID == "" || comments[0].CreatedAt.IsZero() {
		t.Fatalf("invalid comment: %+v", comments[0])
	}
	store, err = NewCommentsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.List("app-owner-a", "", "author"); len(got) != 1 || got[0] != comments[0] {
		t.Fatalf("comment did not survive restart: %v", got)
	}
	if got := store.List("app-owner-b", "", "author"); len(got) != 0 {
		t.Fatalf("another owner inherited comments: %v", got)
	}
	if _, err := store.Delete("app-owner-a", comments[0].ID, "", "stranger"); !errors.Is(err, ErrCommentNotFound) {
		t.Fatalf("stranger was able to delete comment: %v", err)
	}
	if _, err := store.Delete("app-owner-a", comments[0].ID, "", "author"); err != nil {
		t.Fatal(err)
	}
	store, err = NewCommentsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.List("app-owner-a", "", "author")) != 0 {
		t.Fatal("deleted comment reappeared after restart")
	}
	if _, err := store.Delete("app-owner-a", comments[0].ID, "", "author"); !errors.Is(err, ErrCommentNotFound) {
		t.Fatalf("missing comment: %v", err)
	}
}

func TestCommentsRejectEmptyOversizeAndFullThreads(t *testing.T) {
	store, err := NewCommentsStore(filepath.Join(t.TempDir(), "comments.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"", " \n\t ", strings.Repeat("x", types.CommentMaxLength+1)} {
		if _, err := store.Add("app", text, "", "author"); !errors.Is(err, ErrCommentInvalid) {
			t.Fatalf("invalid text accepted: %v", err)
		}
	}
	for range commentsMaxPerApp {
		if _, err := store.Add("app", "A comment", "", "author"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Add("app", "One too many", "", "author"); !errors.Is(err, ErrCommentCapacity) {
		t.Fatalf("full thread accepted another comment: %v", err)
	}
	if len(store.List("app", "", "author")) != commentsMaxPerApp {
		t.Fatal("capacity rejection changed the thread")
	}
}

func TestCommentsFailedWriteDoesNotPublishComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "comments.json")
	store, err := NewCommentsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the destination makes atomic replacement fail on all OSes.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("app", "Not saved", "", "author"); err == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	if len(store.List("app", "", "author")) != 0 {
		t.Fatal("failed write published a non-durable comment")
	}
}
