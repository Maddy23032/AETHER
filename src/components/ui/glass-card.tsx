import * as React from "react";
import { motion, HTMLMotionProps } from "framer-motion";
import { cn } from "@/lib/utils";

interface GlassCardProps extends HTMLMotionProps<"div"> {
  active?: boolean;
  glow?: "indigo" | "rose" | "emerald" | "none";
}

const GlassCard = React.forwardRef<HTMLDivElement, GlassCardProps>(
  ({ className, active = false, glow = "none", children, ...props }, ref) => {
    const glowClasses = {
      indigo: "glow-indigo",
      rose: "glow-rose",
      emerald: "glow-emerald",
      none: "",
    };

    return (
      <motion.div
        ref={ref}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className={cn(
          active ? "glass-card-active" : "glass-card",
          glowClasses[glow],
          "p-6",
          className
        )}
        {...props}
      >
        {children}
      </motion.div>
    );
  }
);
GlassCard.displayName = "GlassCard";

export { GlassCard };