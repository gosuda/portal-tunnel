import type { JSX } from "react";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type TagComboboxProps = {
  availableTags: string[];
  selectedTags: string[];
  onAdd: (tag: string) => void;
  onRemove: (tag: string) => void;
};

const MAX_TAG_OPTIONS = 8;

function filterTagOptions(
  availableTags: string[],
  selectedTags: string[],
  inputValue: string
): string[] {
  const query = inputValue.trim().toLowerCase();
  const pool = availableTags.filter((tag) => !selectedTags.includes(tag));
  if (query === "") {
    return pool.slice(0, MAX_TAG_OPTIONS);
  }
  return pool.filter((tag) => tag.toLowerCase().includes(query)).slice(0, MAX_TAG_OPTIONS);
}

function moveActiveIndex(length: number, current: number, delta: number): number {
  if (length === 0) {
    return 0;
  }
  return (current + delta + length) % length;
}

function tagForCommit(
  open: boolean,
  options: string[],
  activeIndex: number,
  inputValue: string
): string | null {
  if (open && options[activeIndex] !== undefined) {
    return options[activeIndex];
  }
  const draft = inputValue.trim();
  return draft === "" ? null : draft;
}

function measureDropdownPanel(el: HTMLDivElement | null): React.CSSProperties | undefined {
  if (!el) {
    return undefined;
  }
  const rect = el.getBoundingClientRect();
  return {
    position: "absolute",
    top: rect.bottom + window.scrollY + 4,
    left: rect.left + window.scrollX,
    width: rect.width,
    zIndex: 50,
  };
}

function commitTagSelection(tag: string, selectedTags: string[], onAdd: (tag: string) => void, setInputValue: (value: string) => void, setOpen: (open: boolean) => void): void {
  if (!tag || selectedTags.includes(tag)) {
    return;
  }
  onAdd(tag);
  setInputValue("");
  setOpen(false);
}

function handleComboboxKey(event: React.KeyboardEvent<HTMLInputElement>, state: { open: boolean; filtered: string[]; activeIndex: number; inputValue: string }, controls: { openDropdown: () => void; closeDropdown: () => void; moveActive: (delta: number) => void; commit: (tag: string) => void }): void {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    controls.openDropdown();
    controls.moveActive(event.key === "ArrowDown" ? 1 : -1);
    return;
  }
  if (event.key === "Enter") {
    event.preventDefault();
    const tag = tagForCommit(state.open, state.filtered, state.activeIndex, state.inputValue);
    if (tag !== null) {
      controls.commit(tag);
    }
    return;
  }
  if (event.key === "Escape") {
    controls.closeDropdown();
  }
}

function SelectedTags({ selectedTags, onRemove }: { selectedTags: string[]; onRemove: (tag: string) => void }): JSX.Element {
  return (
    <>
      {selectedTags.map((tag) => (
        <Button
          key={tag}
          variant="secondary"
          size="sm"
          className="h-7 rounded-md px-3 bg-secondary text-primary text-xs"
          onClick={() => onRemove(tag)}
          aria-label={`Remove tag ${tag}`}
        >
          {tag}
          <span className="ml-2 bg-secondary text-primary">×</span>
        </Button>
      ))}
    </>
  );
}

function TagOptionDropdown({ open, options, panelStyle, activeIndex, listId, onSelect }: {
  open: boolean;
  options: string[];
  panelStyle: React.CSSProperties | undefined;
  activeIndex: number;
  listId: string;
  onSelect: (tag: string) => void;
}): React.ReactNode {
  if (!open || options.length === 0 || !panelStyle) {
    return null;
  }
  return createPortal(
    <div
      style={panelStyle}
      className="rounded-md border border-border bg-background shadow-lg overflow-hidden"
    >
      <ul
        id={listId}
        role="listbox"
        className="max-h-56 overflow-auto py-1"
      >
        {options.map((tag, idx) => (
          <li key={tag} role="option" aria-selected={idx === activeIndex}>
            <button
              type="button"
              className={cn(
                "flex w-full items-center px-3 py-2 text-left text-sm transition-colors",
                idx === activeIndex
                  ? "bg-primary/20 text-foreground"
                  : "hover:bg-border/60"
              )}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => onSelect(tag)}
            >
              {tag}
            </button>
          </li>
        ))}
      </ul>
    </div>,
    document.body
  );
}

export function TagCombobox({
  availableTags,
  selectedTags,
  onAdd,
  onRemove,
}: TagComboboxProps): JSX.Element {
  const [inputValue, setInputValue] = useState("");
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const listId = "tag-combobox-list";
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [panelStyle, setPanelStyle] = useState<React.CSSProperties>();

  const filtered = useMemo(
    () => filterTagOptions(availableTags, selectedTags, inputValue),
    [availableTags, selectedTags, inputValue]
  );

  useEffect(() => {
    setActiveIndex(0);
  }, [filtered.length]);

  useEffect(() => {
    if (!open) return;
    const updatePosition = () => {
      setPanelStyle(measureDropdownPanel(containerRef.current));
    };
    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open]);

  const addTag = (tag: string) => {
    commitTagSelection(tag, selectedTags, onAdd, setInputValue, setOpen);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    handleComboboxKey(e, { open, filtered, activeIndex, inputValue }, {
      openDropdown: () => setOpen(true),
      closeDropdown: () => setOpen(false),
      moveActive: (delta: number) => setActiveIndex((i) => moveActiveIndex(filtered.length, i, delta)),
      commit: addTag,
    });
  };

  const BLUR_CLOSE_DELAY_MS = 100;

  const handleBlur = () => {
    setTimeout(() => setOpen(false), BLUR_CLOSE_DELAY_MS);
  };

  return (
    <div
      ref={containerRef}
      className="flex w-full sm:w-auto sm:min-w-[320px] flex-1 items-center gap-2 overflow-visible"
    >
      <div className="flex min-w-0 flex-1 items-center gap-2 rounded-md border border-border bg-background px-2 py-1.5 min-h-10">
        <div className="flex flex-1 flex-wrap items-center gap-2 overflow-hidden">
          <SelectedTags selectedTags={selectedTags} onRemove={onRemove} />
          <input
            ref={inputRef}
            value={inputValue}
            onChange={(e) => {
              setInputValue(e.target.value);
              setOpen(true);
            }}
            onFocus={() => setOpen(true)}
            onClick={() => setOpen(true)}
            onBlur={handleBlur}
            onKeyDown={handleKeyDown}
            placeholder="Add tag…"
            className="min-w-30 flex-1 bg-transparent text-sm outline-none placeholder:text-text-muted"
            role="combobox"
            aria-expanded={open}
            aria-controls={listId}
            aria-autocomplete="list"
          />
        </div>
      </div>

      <TagOptionDropdown
        open={open}
        options={filtered}
        panelStyle={panelStyle}
        activeIndex={activeIndex}
        listId={listId}
        onSelect={addTag}
      />
    </div>
  );
}
