import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const statusBadgeVariants = cva(
  "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        critical: "bg-destructive/20 text-destructive border border-destructive/30",
        high: "bg-warning/20 text-warning border border-warning/30",
        medium: "bg-primary/20 text-primary border border-primary/30",
        low: "bg-muted text-muted-foreground border border-border",
        safe: "bg-success/20 text-success border border-success/30",
        info: "bg-primary/10 text-primary border border-primary/20",
      },
    },
    defaultVariants: {
      variant: "info",
    },
  }
);

export interface StatusBadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof statusBadgeVariants> {
  dot?: boolean;
}

const StatusBadge = React.forwardRef<HTMLSpanElement, StatusBadgeProps>(
  ({ className, variant, dot = false, children, ...props }, ref) => {
    return (
      <span
        ref={ref}
        className={cn(statusBadgeVariants({ variant }), className)}
        {...props}
      >
        {dot && (
          <span
            className={cn(
              "w-1.5 h-1.5 rounded-full",
              variant === "critical" && "bg-destructive",
              variant === "high" && "bg-warning",
              variant === "medium" && "bg-primary",
              variant === "low" && "bg-muted-foreground",
              variant === "safe" && "bg-success",
              variant === "info" && "bg-primary"
            )}
          />
        )}
        {children}
      </span>
    );
  }
);
StatusBadge.displayName = "StatusBadge";

export { StatusBadge, statusBadgeVariants };