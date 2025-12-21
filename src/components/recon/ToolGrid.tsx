/**
 * ToolGrid Component
 * Grid display of available reconnaissance tools
 */

import { useState, useMemo } from "react";
import { ToolCard } from "./ToolCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { RECON_TOOLS, TOOL_CATEGORIES } from "@/services/reconService";
import type { ToolId, ToolCategory, ReconTool } from "@/services/types/recon.types";
import { Search, CheckSquare, Square, Filter } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface ToolGridProps {
  selectedTools: ToolId[];
  onToolToggle: (toolId: ToolId) => void;
  onSelectAll: () => void;
  onDeselectAll: () => void;
  disabled?: boolean;
}

export function ToolGrid({
  selectedTools,
  onToolToggle,
  onSelectAll,
  onDeselectAll,
  disabled = false,
}: ToolGridProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<ToolCategory[]>([]);

  // Filter tools based on search and category
  const filteredTools = useMemo(() => {
    return RECON_TOOLS.filter((tool) => {
      // Search filter
      const matchesSearch =
        searchQuery === "" ||
        tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchQuery.toLowerCase());

      // Category filter
      const matchesCategory =
        categoryFilter.length === 0 || categoryFilter.includes(tool.category);

      return matchesSearch && matchesCategory;
    });
  }, [searchQuery, categoryFilter]);

  // Group tools by category
  const toolsByCategory = useMemo(() => {
    const grouped: Record<string, ReconTool[]> = {};
    for (const tool of filteredTools) {
      if (!grouped[tool.category]) {
        grouped[tool.category] = [];
      }
      grouped[tool.category].push(tool);
    }
    return grouped;
  }, [filteredTools]);

  const toggleCategory = (category: ToolCategory) => {
    setCategoryFilter((prev) =>
      prev.includes(category)
        ? prev.filter((c) => c !== category)
        : [...prev, category]
    );
  };

  const allSelected = selectedTools.length === RECON_TOOLS.length;

  return (
    <div className="space-y-4">
      {/* Header with search and filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search tools..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-muted/50"
            disabled={disabled}
          />
        </div>

        {/* Category filter */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="gap-2" disabled={disabled}>
              <Filter className="w-4 h-4" />
              Category
              {categoryFilter.length > 0 && (
                <Badge variant="secondary" className="ml-1 px-1.5">
                  {categoryFilter.length}
                </Badge>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            {Object.entries(TOOL_CATEGORIES).map(([key, cat]) => (
              <DropdownMenuCheckboxItem
                key={key}
                checked={categoryFilter.includes(key as ToolCategory)}
                onCheckedChange={() => toggleCategory(key as ToolCategory)}
              >
                {cat.name}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Select all / Deselect all */}
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={allSelected ? onDeselectAll : onSelectAll}
            disabled={disabled}
            className="gap-2"
          >
            {allSelected ? (
              <>
                <Square className="w-4 h-4" />
                Deselect All
              </>
            ) : (
              <>
                <CheckSquare className="w-4 h-4" />
                Select All
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Selection summary */}
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <span>
          {selectedTools.length} of {RECON_TOOLS.length} tools selected
        </span>
        {selectedTools.length > 0 && (
          <>
            <span>•</span>
            <span className="flex flex-wrap gap-1">
              {selectedTools.slice(0, 5).map((id) => (
                <Badge key={id} variant="secondary" className="text-xs">
                  {id}
                </Badge>
              ))}
              {selectedTools.length > 5 && (
                <Badge variant="secondary" className="text-xs">
                  +{selectedTools.length - 5} more
                </Badge>
              )}
            </span>
          </>
        )}
      </div>

      {/* Tools grid */}
      {Object.keys(toolsByCategory).length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          No tools match your search criteria
        </div>
      ) : (
        <div className="space-y-6">
          {Object.entries(toolsByCategory).map(([category, tools]) => (
            <div key={category}>
              <h4 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2">
                {TOOL_CATEGORIES[category as ToolCategory]?.name || category}
                <Badge variant="outline" className="text-xs">
                  {tools.length}
                </Badge>
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {tools.map((tool) => (
                  <ToolCard
                    key={tool.id}
                    tool={tool}
                    isSelected={selectedTools.includes(tool.id)}
                    onToggle={() => onToolToggle(tool.id)}
                    disabled={disabled}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ToolGrid;
