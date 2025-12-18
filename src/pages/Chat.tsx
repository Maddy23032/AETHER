import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bot, User, Send, FileText, Sparkles, ArrowRight } from "lucide-react";
import { GlassCard } from "@/components/ui/glass-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";

interface Message {
  id: number;
  role: "user" | "assistant";
  content: string;
}

const initialMessages: Message[] = [
  {
    id: 1,
    role: "assistant",
    content:
      "Hello, Operator. I've analyzed the latest scan results. I found 3 critical issues that require immediate attention. The SQL injection vulnerability on the /login endpoint is the highest priority.",
  },
  {
    id: 2,
    role: "user",
    content: "Tell me more about the SQL injection vulnerability.",
  },
  {
    id: 3,
    role: "assistant",
    content:
      "The SQL injection was detected on POST /api/v1/login. The 'username' parameter is vulnerable to boolean-based blind injection. An attacker could bypass authentication or extract sensitive data. I recommend implementing parameterized queries and input validation immediately.",
  },
];

const mockReferences = [
  { id: 1, name: "Scan_Report_404.pdf", type: "report" },
  { id: 2, name: "Nmap_Scan_Results.txt", type: "log" },
  { id: 3, name: "OWASP_SQLi_Guide.md", type: "reference" },
  { id: 4, name: "API_Schema_v1.json", type: "schema" },
];

const suggestedPrompts = [
  "Generate a remediation plan",
  "Prioritize vulnerabilities by risk",
  "Create a security report",
];

export default function Chat() {
  const [messages, setMessages] = useState<Message[]>(initialMessages);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  const sendMessage = () => {
    if (!input.trim()) return;

    const userMessage: Message = {
      id: messages.length + 1,
      role: "user",
      content: input,
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsTyping(true);

    // Simulate AI response
    setTimeout(() => {
      const aiMessage: Message = {
        id: messages.length + 2,
        role: "assistant",
        content:
          "Based on my analysis, here's a prioritized remediation plan:\n\n1. **Critical (Fix Immediately)**\n   - SQL Injection on /login - Implement parameterized queries\n   - RCE on /admin/upload - Add file type validation\n\n2. **High (Fix This Week)**\n   - XSS on /search - Sanitize user input\n   - IDOR on /api/users - Implement proper authorization checks\n\n3. **Medium (Fix This Sprint)**\n   - Missing security headers - Add CSP, X-Frame-Options\n\nWould you like me to generate code snippets for any of these fixes?",
      };
      setMessages((prev) => [...prev, aiMessage]);
      setIsTyping(false);
    }, 2000);
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex gap-6">
      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        <div className="mb-4">
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-primary" />
            Aether Intelligence
          </h1>
          <p className="text-muted-foreground">AI-powered security analysis assistant</p>
        </div>

        <GlassCard className="flex-1 flex flex-col p-0 overflow-hidden">
          {/* Messages */}
          <ScrollArea className="flex-1 p-4">
            <div className="space-y-4">
              <AnimatePresence>
                {messages.map((message) => (
                  <motion.div
                    key={message.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`flex gap-3 ${
                      message.role === "user" ? "justify-end" : "justify-start"
                    }`}
                  >
                    {message.role === "assistant" && (
                      <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
                        <Bot className="w-4 h-4 text-primary" />
                      </div>
                    )}
                    <div
                      className={`max-w-[80%] p-4 rounded-lg ${
                        message.role === "user"
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted/50 text-foreground"
                      }`}
                    >
                      <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                    </div>
                    {message.role === "user" && (
                      <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center shrink-0">
                        <User className="w-4 h-4 text-muted-foreground" />
                      </div>
                    )}
                  </motion.div>
                ))}
              </AnimatePresence>

              {isTyping && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex gap-3"
                >
                  <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
                    <Bot className="w-4 h-4 text-primary" />
                  </div>
                  <div className="bg-muted/50 p-4 rounded-lg">
                    <div className="flex gap-1">
                      <span className="w-2 h-2 rounded-full bg-muted-foreground animate-bounce" />
                      <span
                        className="w-2 h-2 rounded-full bg-muted-foreground animate-bounce"
                        style={{ animationDelay: "0.1s" }}
                      />
                      <span
                        className="w-2 h-2 rounded-full bg-muted-foreground animate-bounce"
                        style={{ animationDelay: "0.2s" }}
                      />
                    </div>
                  </div>
                </motion.div>
              )}
            </div>
          </ScrollArea>

          {/* Suggested Prompts */}
          <div className="px-4 pb-2">
            <div className="flex gap-2 flex-wrap">
              {suggestedPrompts.map((prompt) => (
                <Button
                  key={prompt}
                  variant="outline"
                  size="sm"
                  className="text-xs"
                  onClick={() => setInput(prompt)}
                >
                  {prompt}
                  <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              ))}
            </div>
          </div>

          {/* Input */}
          <div className="p-4 border-t border-border">
            <div className="flex gap-2">
              <Input
                placeholder="Ask about vulnerabilities, request analysis..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                className="flex-1 bg-muted/50"
              />
              <Button onClick={sendMessage} disabled={!input.trim() || isTyping}>
                <Send className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* Context Panel */}
      <div className="hidden lg:block w-80">
        <GlassCard className="h-full">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-4">
            References
          </h3>

          <div className="space-y-2">
            {mockReferences.map((ref) => (
              <motion.div
                key={ref.id}
                whileHover={{ x: 4 }}
                className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
              >
                <FileText className="w-4 h-4 text-muted-foreground" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{ref.name}</p>
                  <p className="text-xs text-muted-foreground capitalize">{ref.type}</p>
                </div>
              </motion.div>
            ))}
          </div>

          <div className="mt-6 pt-4 border-t border-border">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
              Analysis Context
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last Scan</span>
                <span>2 hours ago</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total Findings</span>
                <span>14 issues</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Coverage</span>
                <span>87%</span>
              </div>
            </div>
          </div>
        </GlassCard>
      </div>
    </div>
  );
}