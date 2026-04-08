import { useCallback, useEffect, useMemo, useState } from "react";
import type { SortOption, StatusFilter } from "@/types/filters";

export interface BaseServer {
  id: number;
  name: string;
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
  online: boolean;
  dns: string;
  link: string;
  lastUpdated?: string;
  firstSeen?: string;
}

export interface UseListOptions<T extends BaseServer> {
  servers: T[];
  storageKey: string;
  additionalFilter?: (server: T) => boolean;
}

export interface UseListReturn<T extends BaseServer> {
  searchQuery: string;
  status: StatusFilter;
  sortBy: SortOption;
  selectedTags: string[];
  favorites: number[];
  availableTags: string[];
  filteredServers: T[];
  handleSearchChange: (value: string) => void;
  handleStatusChange: (value: StatusFilter) => void;
  handleSortByChange: (value: SortOption) => void;
  handleTagToggle: (tag: string) => void;
  handleToggleFavorite: (serverId: number) => void;
}

function readStoredFavorites(storageKey: string): number[] {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(storageKey);
  } catch {
    return [];
  }

  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return [...new Set(
      parsed.filter(
        (value): value is number => Number.isInteger(value) && value > 0
      )
    )];
  } catch {
    return [];
  }
}

function parseTimestamp(value?: string, fallback = 0): number {
  if (!value) {
    return fallback;
  }

  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function matchesStatus(online: boolean, status: StatusFilter): boolean {
  switch (status) {
    case "online":
      return online;
    case "offline":
      return !online;
    default:
      return true;
  }
}

export function useList<T extends BaseServer>({
  servers,
  storageKey,
  additionalFilter,
}: UseListOptions<T>): UseListReturn<T> {
  const [searchQuery, setSearchQuery] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [sortBy, setSortBy] = useState<SortOption>("duration");
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [favorites, setFavorites] = useState<number[]>(() =>
    readStoredFavorites(storageKey)
  );

  useEffect(() => {
    setFavorites(readStoredFavorites(storageKey));
  }, [storageKey]);

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(favorites));
    } catch {
      // Ignore storage write failures (quota/private browsing).
    }
  }, [favorites, storageKey]);

  const availableTags = useMemo(() => {
    const counts = new Map<string, number>();
    servers.forEach((server) => {
      server.tags.forEach((tag) => {
        const normalizedTag = typeof tag === "string" ? tag.trim().toLowerCase() : "";
        if (!normalizedTag) {
          return;
        }
        counts.set(normalizedTag, (counts.get(normalizedTag) || 0) + 1);
      });
    });

    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([tag]) => tag);
  }, [servers]);

  useEffect(() => {
    const validIDs = new Set(servers.map((server) => server.id));
    setFavorites((prev) => {
      const next = prev.filter((id) => validIDs.has(id));
      return next.length === prev.length ? prev : next;
    });
  }, [servers]);

  useEffect(() => {
    const availableTagSet = new Set(availableTags);
    setSelectedTags((prev) => {
      const next = prev.filter((tag) => availableTagSet.has(tag));
      return next.length === prev.length ? prev : next;
    });
  }, [availableTags]);

  const filteredServers = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const selectedTagSet = new Set(selectedTags);
    const favoriteSet = new Set(favorites);
    const now = Date.now();

    const matchesTags = (server: T): boolean => {
      if (selectedTagSet.size === 0) {
        return true;
      }

      return server.tags.some((tag) => selectedTagSet.has(tag.toLowerCase().trim()));
    };

    const matchesSearch = (server: T): boolean => {
      if (query === "") {
        return true;
      }

      return (
        server.name.toLowerCase().includes(query) ||
        server.description.toLowerCase().includes(query) ||
        server.tags.some((tag) => tag.toLowerCase().includes(query))
      );
    };

    const filtered = servers.filter((server) => {
      const matchesAdditional = additionalFilter ? additionalFilter(server) : true;

      return (
        matchesSearch(server) &&
        matchesStatus(server.online, status) &&
        matchesTags(server) &&
        matchesAdditional
      );
    });

    const sortByField = (sortValue: SortOption) => {
      switch (sortValue) {
        case "name-asc":
          return (a: T, b: T) => a.name.localeCompare(b.name);
        case "name-desc":
          return (a: T, b: T) => b.name.localeCompare(a.name);
        case "updated":
          return (a: T, b: T) =>
            parseTimestamp(b.lastUpdated, 0) - parseTimestamp(a.lastUpdated, 0);
        case "duration":
          return (a: T, b: T) =>
            parseTimestamp(a.firstSeen, now) - parseTimestamp(b.firstSeen, now);
        case "description":
          return (a: T, b: T) => a.description.localeCompare(b.description);
        case "tags":
          return (a: T, b: T) => (a.tags[0] || "").localeCompare(b.tags[0] || "");
        case "owner":
          return (a: T, b: T) => a.owner.localeCompare(b.owner);
        case "default":
          return (a: T, b: T) => a.id - b.id;
        default:
          return (a: T, b: T) => a.id - b.id;
      }
    };

    const sorted = [...filtered].sort(sortByField(sortBy));
    sorted.sort((a, b) => {
      const aIsFav = favoriteSet.has(a.id);
      const bIsFav = favoriteSet.has(b.id);
      if (aIsFav && !bIsFav) return -1;
      if (!aIsFav && bIsFav) return 1;
      return 0;
    });

    return sorted;
  }, [servers, searchQuery, status, sortBy, selectedTags, favorites, additionalFilter]);

  const handleSearchChange = useCallback((value: string) => {
    setSearchQuery(value);
  }, []);

  const handleStatusChange = useCallback((value: StatusFilter) => {
    setStatus(value);
  }, []);

  const handleSortByChange = useCallback((value: SortOption) => {
    setSortBy(value);
  }, []);

  const handleTagToggle = useCallback((tag: string) => {
    const normalizedTag = tag.trim().toLowerCase();
    if (!normalizedTag) {
      return;
    }

    setSelectedTags((prev) =>
      prev.includes(normalizedTag)
        ? prev.filter((candidate) => candidate !== normalizedTag)
        : [...prev, normalizedTag]
    );
  }, []);

  const handleToggleFavorite = useCallback((serverId: number) => {
    setFavorites((prev) =>
      prev.includes(serverId)
        ? prev.filter((id) => id !== serverId)
        : [...prev, serverId]
    );
  }, []);

  return {
    searchQuery,
    status,
    sortBy,
    selectedTags,
    favorites,
    availableTags,
    filteredServers,
    handleSearchChange,
    handleStatusChange,
    handleSortByChange,
    handleTagToggle,
    handleToggleFavorite,
  };
}
