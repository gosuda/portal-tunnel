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

export function TagCombobox({
  availableTags,
  selectedTags,
  onAdd,
  onRemove,
}: TagComboboxProps) {
  const [inputValue, setInputValue] = useState("");
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const listId = "tag-combobox-list";
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [panelStyle, setPanelStyle] = useState<React.CSSProperties>();

  const filtered = useMemo(() => {
    const query = inputValue.trim().toLowerCase();
    const pool = availableTags.filter((tag) => !selectedTags.includes(tag));
    if (!query) return pool.slice(0, 8);
    return pool.filter((tag) => tag.toLowerCase().includes(query)).slice(0, 8);
  }, [availableTags, selectedTags, inputValue]);

  useEffect(() => {
    setActiveIndex(0);
  }, [filtered.length]);

  useEffect(() => {
    if (!open) return;
    const updatePosition = () => {
      const el = containerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      setPanelStyle({
        position: "absolute",
        top: rect.bottom + window.scrollY + 4,
        left: rect.left + window.scrollX,
        width: rect.width,
        zIndex: 50,
      });
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
    if (!tag || selectedTags.includes(tag)) return;
    onAdd(tag);
    setInputValue("");
    setOpen(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setOpen(true);
      setActiveIndex((i) => (i + 1) % Math.max(filtered.length, 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setOpen(true);
      setActiveIndex((i) =>
        filtered.length === 0 ? 0 : (i - 1 + filtered.length) % filtered.length
      );
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (open && filtered[activeIndex]) {
        addTag(filtered[activeIndex]);
      } else if (inputValue.trim()) {
        addTag(inputValue.trim());
      }
    } else if (e.key === "Escape") {
      setOpen(false);
    }
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

      {open &&
        filtered.length > 0 &&
        panelStyle &&
        createPortal(
          <div
            style={panelStyle}
            className="rounded-md border border-border bg-background shadow-lg overflow-hidden"
          >
            <ul
              id={listId}
              role="listbox"
              className="max-h-56 overflow-auto py-1"
            >
              {filtered.map((tag, idx) => (
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
                    onClick={() => addTag(tag)}
                  >
                    {tag}
                  </button>
                </li>
              ))}
            </ul>
          </div>,
          document.body
        )}
    </div>
  );
}
