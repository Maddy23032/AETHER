import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bot, User, Send, FileText, Sparkles, ArrowRight, AlertCircle, Loader2, RefreshCw, Paperclip, X, Image, FileCode, File, RotateCcw, Maximize2, Minimize2, Copy, Check } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "sonner";
import { GlassCard } from "@/components/ui/glass-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  sendChatMessage,
  getSuggestedPrompts,
  getContextStats,
  getReferences,
  checkHealth,
  type ChatMessage as APIChatMessage,
  type SourceReference,
  type SuggestedPrompt,
  type AnalysisContextStats,
  type Reference,
  getSourceTypeInfo,
} from "@/services/intelligenceService";

// Attachment interface - for serialization, we need a simpler version
interface AttachmentData {
  id: string;
  name: string;
  size: number;
  type: 'image' | 'document' | 'scan_log' | 'other';
  preview?: string;  // Base64 preview for images
}

interface Attachment {
  id: string;
  file: File;
  type: 'image' | 'document' | 'scan_log' | 'other';
  preview?: string;  // Base64 preview for images
}

interface Message {
  id: number;
  role: "user" | "assistant";
  content: string;
  sources?: SourceReference[];
  thinking?: string;
  attachments?: Attachment[];
  attachmentData?: AttachmentData[];  // Serializable version for persistence
}

// Storage key for chat persistence
const CHAT_STORAGE_KEY = 'aether_intelligence_chat';

// Serializable message for storage (without File objects)
interface StoredMessage {
  id: number;
  role: "user" | "assistant";
  content: string;
  sources?: SourceReference[];
  thinking?: string;
  attachmentData?: AttachmentData[];
}

export default function Chat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [isOnline, setIsOnline] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hasLoadedChat, setHasLoadedChat] = useState(false);
  
  // File upload state
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [copiedMessageId, setCopiedMessageId] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  // Context panel state
  const [suggestedPrompts, setSuggestedPrompts] = useState<SuggestedPrompt[]>([]);
  const [contextStats, setContextStats] = useState<AnalysisContextStats | null>(null);
  const [references, setReferences] = useState<Reference[]>([]);
  
  const scrollRef = useRef<HTMLDivElement>(null);

  // Load persisted chat on mount
  useEffect(() => {
    if (hasLoadedChat) return;
    
    try {
      const stored = localStorage.getItem(CHAT_STORAGE_KEY);
      if (stored) {
        const storedMessages: StoredMessage[] = JSON.parse(stored);
        // Convert stored messages back to Message format
        const restoredMessages: Message[] = storedMessages.map(msg => ({
          ...msg,
          // Restore attachmentData as a display-only format
          attachments: undefined,
        }));
        if (restoredMessages.length > 0) {
          setMessages(restoredMessages);
          setHasLoadedChat(true);
          return;
        }
      }
    } catch (err) {
      console.warn('Failed to load persisted chat:', err);
    }
    setHasLoadedChat(true);
  }, [hasLoadedChat]);

  // Persist messages to localStorage whenever they change
  useEffect(() => {
    if (!hasLoadedChat || messages.length === 0) return;
    
    try {
      // Convert to storable format (remove File objects)
      const storable: StoredMessage[] = messages.map(msg => ({
        id: msg.id,
        role: msg.role,
        content: msg.content,
        sources: msg.sources,
        thinking: msg.thinking,
        attachmentData: msg.attachments?.map(a => ({
          id: a.id,
          name: a.file.name,
          size: a.file.size,
          type: a.type,
          preview: a.preview,
        })) || msg.attachmentData,
      }));
      localStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(storable));
    } catch (err) {
      console.warn('Failed to persist chat:', err);
    }
  }, [messages, hasLoadedChat]);

  // Check API health on mount
  useEffect(() => {
    const checkApiHealth = async () => {
      try {
        await checkHealth();
        setIsOnline(true);
        setError(null);
        
        // Load initial data
        loadSuggestedPrompts();
        loadContextStats();
        loadReferences();
      } catch {
        setIsOnline(false);
        setError("Intelligence API is offline. Please start the backend server.");
      }
    };
    
    checkApiHealth();
  }, []);
  
  // Add welcome message only if no chat history exists after loading
  useEffect(() => {
    if (hasLoadedChat && messages.length === 0 && isOnline) {
      setMessages([{
        id: 1,
        role: "assistant",
        content: "Hello, Operator. I'm AETHER Intelligence, your AI-powered security analysis assistant. I have access to your scan results and can help you analyze vulnerabilities, prioritize risks, and create remediation plans.\n\nWhat would you like to know?",
      }]);
    }
  }, [hasLoadedChat, isOnline, messages.length]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isTyping]);

  const loadSuggestedPrompts = async () => {
    try {
      const prompts = await getSuggestedPrompts();
      setSuggestedPrompts(prompts.slice(0, 4)); // Show first 4
    } catch (err) {
      console.error("Failed to load suggested prompts:", err);
      // Fallback prompts
      setSuggestedPrompts([
        { text: "Analyze the latest scan results", category: "security" },
        { text: "What are the critical vulnerabilities?", category: "vulnerability" },
        { text: "Generate a remediation plan", category: "security" },
      ]);
    }
  };

  const loadContextStats = async () => {
    try {
      const stats = await getContextStats();
      setContextStats(stats);
    } catch (err) {
      console.error("Failed to load context stats:", err);
    }
  };

  const loadReferences = async () => {
    try {
      const response = await getReferences(undefined, undefined, 10);
      setReferences(response.references);
    } catch (err) {
      console.error("Failed to load references:", err);
    }
  };

  const sendMessage = async () => {
    if ((!input.trim() && attachments.length === 0) || isTyping) return;
    
    // Build message content with attachment info
    let messageContent = input.trim();
    if (attachments.length > 0) {
      const attachmentInfo = attachments.map(a => `[Attached: ${a.file.name}]`).join(' ');
      if (messageContent) {
        messageContent = `${messageContent}\n\n${attachmentInfo}`;
      } else {
        messageContent = attachmentInfo;
      }
    }
    
    const userMessage: Message = {
      id: messages.length + 1,
      role: "user",
      content: messageContent,
      attachments: attachments.length > 0 ? [...attachments] : undefined,
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setAttachments([]);  // Clear attachments after sending
    setIsTyping(true);
    setError(null);

    try {
      // Build conversation history for context
      const conversationHistory: APIChatMessage[] = messages.slice(-10).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const response = await sendChatMessage({
        message: input,
        conversation_history: conversationHistory,
        include_scan_context: true,
      });

      const aiMessage: Message = {
        id: messages.length + 2,
        role: "assistant",
        content: response.message,
        sources: response.sources,
        thinking: response.thinking,
      };

      setMessages((prev) => [...prev, aiMessage]);
      
      // Refresh references if new sources were used
      if (response.sources?.length) {
        loadReferences();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to send message");
      // Remove the user message if failed
      setMessages((prev) => prev.slice(0, -1));
    } finally {
      setIsTyping(false);
    }
  };

  const handlePromptClick = (prompt: string) => {
    setInput(prompt);
  };

  // File upload handlers
  const getFileType = (file: File): 'image' | 'document' | 'scan_log' | 'other' => {
    if (file.type.startsWith('image/')) return 'image';
    if (file.name.endsWith('.log') || file.name.endsWith('.txt') || file.name.endsWith('.nmap')) return 'scan_log';
    if (file.type.includes('pdf') || file.type.includes('document') || file.name.endsWith('.md')) return 'document';
    return 'other';
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;

    const newAttachments: Attachment[] = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const attachment: Attachment = {
        id: `${Date.now()}-${i}`,
        file,
        type: getFileType(file),
      };

      // Generate preview for images
      if (attachment.type === 'image') {
        const reader = new FileReader();
        const preview = await new Promise<string>((resolve) => {
          reader.onload = (e) => resolve(e.target?.result as string);
          reader.readAsDataURL(file);
        });
        attachment.preview = preview;
      }

      newAttachments.push(attachment);
    }

    setAttachments((prev) => [...prev, ...newAttachments]);
    
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removeAttachment = (id: string) => {
    setAttachments((prev) => prev.filter((a) => a.id !== id));
  };

  const getAttachmentIcon = (type: Attachment['type']) => {
    switch (type) {
      case 'image':
        return <Image className="w-4 h-4" />;
      case 'scan_log':
        return <FileCode className="w-4 h-4" />;
      case 'document':
        return <FileText className="w-4 h-4" />;
      default:
        return <File className="w-4 h-4" />;
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getSourceIcon = (type: string) => {
    switch (type) {
      case "recon_scan":
        return "🔍";
      case "enum_scan":
        return "🛡️";
      case "document":
        return "📄";
      default:
        return "📁";
    }
  };

  const clearChat = () => {
    localStorage.removeItem(CHAT_STORAGE_KEY);
    setMessages([{
      id: 1,
      role: "assistant",
      content: "Hello, Operator. I'm AETHER Intelligence, your AI-powered security analysis assistant. I have access to your scan results and can help you analyze vulnerabilities, prioritize risks, and create remediation plans.\n\nWhat would you like to know?",
    }]);
  };

  return (
    <div className={`flex gap-6 transition-all duration-300 ${
      isFullscreen 
        ? "fixed inset-0 z-50 bg-background p-4" 
        : "h-[calc(100vh-8rem)]"
    }`}>
      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Sparkles className="w-6 h-6 text-primary" />
              Aether Intelligence
            </h1>
            <p className="text-muted-foreground">AI-powered security analysis assistant</p>
          </div>
          
          {/* Status indicator */}
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setIsFullscreen(!isFullscreen)}
                    className="text-muted-foreground hover:text-foreground"
                  >
                    {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <p>{isFullscreen ? "Exit fullscreen" : "Fullscreen mode"}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearChat}
                    className="text-muted-foreground hover:text-foreground"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <p>Clear chat history</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            {isOnline === null ? (
              <Badge variant="outline" className="flex items-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" />
                Connecting...
              </Badge>
            ) : isOnline ? (
              <Badge variant="outline" className="flex items-center gap-1 text-green-500 border-green-500/50">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                Online
              </Badge>
            ) : (
              <Badge variant="outline" className="flex items-center gap-1 text-red-500 border-red-500/50">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                Offline
              </Badge>
            )}
          </div>
        </div>

        {/* Error Banner */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 flex items-center gap-2 text-destructive"
          >
            <AlertCircle className="w-4 h-4" />
            <span className="text-sm">{error}</span>
          </motion.div>
        )}

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
                    className={`flex gap-3 group relative ${
                      message.role === "user" ? "justify-end" : "justify-start"
                    }`}
                  >
                    {message.role === "assistant" && (
                      <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
                        <Bot className="w-4 h-4 text-primary" />
                      </div>
                    )}
                    <div className="max-w-[80%] space-y-2">
                      {/* Show attachments for user messages */}
                      {message.role === "user" && message.attachments && message.attachments.length > 0 && (
                        <div className="flex flex-wrap gap-2 justify-end">
                          {message.attachments.map((attachment) => (
                            <div
                              key={attachment.id}
                              className="rounded-lg overflow-hidden border border-primary/30 bg-primary/10"
                            >
                              {attachment.type === 'image' && attachment.preview ? (
                                <img
                                  src={attachment.preview}
                                  alt={attachment.file.name}
                                  className="max-w-[200px] max-h-[150px] object-cover"
                                />
                              ) : (
                                <div className="flex items-center gap-2 px-3 py-2">
                                  {getAttachmentIcon(attachment.type)}
                                  <span className="text-xs text-primary-foreground/80 max-w-[150px] truncate">
                                    {attachment.file.name}
                                  </span>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                      {/* Show restored attachmentData (from persisted messages) */}
                      {message.role === "user" && !message.attachments && message.attachmentData && message.attachmentData.length > 0 && (
                        <div className="flex flex-wrap gap-2 justify-end">
                          {message.attachmentData.map((attachment) => (
                            <div
                              key={attachment.id}
                              className="rounded-lg overflow-hidden border border-primary/30 bg-primary/10"
                            >
                              {attachment.type === 'image' && attachment.preview ? (
                                <img
                                  src={attachment.preview}
                                  alt={attachment.name}
                                  className="max-w-[200px] max-h-[150px] object-cover"
                                />
                              ) : (
                                <div className="flex items-center gap-2 px-3 py-2">
                                  {getAttachmentIcon(attachment.type)}
                                  <span className="text-xs text-primary-foreground/80 max-w-[150px] truncate">
                                    {attachment.name}
                                  </span>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                      <div
                        className={`p-4 rounded-lg ${
                          message.role === "user"
                            ? "bg-primary text-primary-foreground"
                            : "bg-muted/50 text-foreground"
                        }`}
                      >
                        {message.role === "assistant" ? (
                          <div className="markdown-content text-sm">
                            <ReactMarkdown 
                              remarkPlugins={[remarkGfm]}
                              components={{
                                h1: ({children}) => <h1 className="text-xl font-bold text-foreground mt-4 mb-3 first:mt-0 border-b border-border pb-2">{children}</h1>,
                                h2: ({children}) => <h2 className="text-lg font-bold text-foreground mt-4 mb-2 first:mt-0">{children}</h2>,
                                h3: ({children}) => <h3 className="text-base font-semibold text-foreground mt-3 mb-2 first:mt-0">{children}</h3>,
                                h4: ({children}) => <h4 className="text-sm font-semibold text-foreground mt-2 mb-1">{children}</h4>,
                                p: ({children}) => <p className="text-foreground leading-relaxed mb-3 last:mb-0">{children}</p>,
                                ul: ({children}) => <ul className="list-disc list-outside ml-5 mb-3 space-y-1.5 text-foreground">{children}</ul>,
                                ol: ({children}) => <ol className="list-decimal list-outside ml-5 mb-3 space-y-1.5 text-foreground">{children}</ol>,
                                li: ({children}) => <li className="text-foreground leading-relaxed pl-1">{children}</li>,
                                strong: ({children}) => <strong className="font-semibold text-primary">{children}</strong>,
                                em: ({children}) => <em className="italic text-muted-foreground">{children}</em>,
                                code: ({children, className}) => {
                                  const isBlock = className?.includes('language-');
                                  return isBlock ? (
                                    <code className={`${className} block`}>{children}</code>
                                  ) : (
                                    <code className="text-primary bg-primary/10 px-1.5 py-0.5 rounded text-[13px] font-mono">{children}</code>
                                  );
                                },
                                pre: ({children}) => <pre className="bg-muted/80 border border-border rounded-lg p-4 my-3 overflow-x-auto text-[13px]">{children}</pre>,
                                blockquote: ({children}) => <blockquote className="border-l-4 border-primary/50 pl-4 my-3 italic text-muted-foreground">{children}</blockquote>,
                                hr: () => <hr className="border-border my-4" />,
                                a: ({href, children}) => <a href={href} className="text-primary hover:underline" target="_blank" rel="noopener noreferrer">{children}</a>,
                                table: ({children}) => <div className="overflow-x-auto my-3"><table className="min-w-full border border-border rounded-lg overflow-hidden">{children}</table></div>,
                                thead: ({children}) => <thead className="bg-muted/50">{children}</thead>,
                                th: ({children}) => <th className="px-3 py-2 text-left text-xs font-semibold text-foreground border-b border-border">{children}</th>,
                                td: ({children}) => <td className="px-3 py-2 text-sm text-foreground border-b border-border/50">{children}</td>,
                              }}
                            >
                              {message.content}
                            </ReactMarkdown>
                          </div>
                        ) : (
                          <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                        )}
                      </div>
                      
                      {/* Show sources for assistant messages */}
                      {message.role === "assistant" && message.sources && message.sources.length > 0 && (
                        <div className="flex flex-wrap gap-1 px-1">
                          {message.sources.slice(0, 3).map((source) => (
                            <Badge
                              key={source.id}
                              variant="outline"
                              className="text-xs bg-muted/30"
                            >
                              {getSourceIcon(source.source_type)} {source.title.slice(0, 30)}
                              {source.title.length > 30 ? "..." : ""}
                            </Badge>
                          ))}
                          {message.sources.length > 3 && (
                            <Badge variant="outline" className="text-xs bg-muted/30">
                              +{message.sources.length - 3} more
                            </Badge>
                          )}
                        </div>
                      )}
                    </div>
                    {message.role === "user" && (
                      <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center shrink-0">
                        <User className="w-4 h-4 text-muted-foreground" />
                      </div>
                    )}
                    {/* Copy button - shown on hover */}
                    <div className="opacity-0 group-hover:opacity-100 transition-opacity absolute -right-2 top-0">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-muted-foreground hover:text-foreground"
                              onClick={() => {
                                navigator.clipboard.writeText(message.content);
                                setCopiedMessageId(message.id);
                                toast.success("Copied to clipboard");
                                setTimeout(() => setCopiedMessageId(null), 2000);
                              }}
                            >
                              {copiedMessageId === message.id ? (
                                <Check className="w-3.5 h-3.5 text-green-500" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent side="left">
                            <p>Copy message</p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
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
              
              <div ref={scrollRef} />
            </div>
          </ScrollArea>

          {/* Suggested Prompts */}
          <div className="px-4 pb-2">
            <div className="flex gap-2 flex-wrap">
              {suggestedPrompts.map((prompt) => (
                <Button
                  key={prompt.text}
                  variant="outline"
                  size="sm"
                  className="text-xs"
                  onClick={() => handlePromptClick(prompt.text)}
                  disabled={!isOnline}
                >
                  {prompt.text.slice(0, 35)}{prompt.text.length > 35 ? "..." : ""}
                  <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              ))}
            </div>
          </div>

          {/* Input */}
          <div className="p-4 border-t border-border">
            {/* Attachment Preview Area */}
            <AnimatePresence>
              {attachments.length > 0 && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="mb-3 p-3 rounded-lg bg-muted/30 border border-border"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-muted-foreground font-medium">
                      {attachments.length} file{attachments.length > 1 ? 's' : ''} attached
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-5 text-xs text-muted-foreground hover:text-destructive"
                      onClick={() => setAttachments([])}
                    >
                      Clear all
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {attachments.map((attachment) => (
                      <motion.div
                        key={attachment.id}
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.8 }}
                        className="relative group"
                      >
                        {attachment.type === 'image' && attachment.preview ? (
                          <div className="relative">
                            <img
                              src={attachment.preview}
                              alt={attachment.file.name}
                              className="h-20 w-20 object-cover rounded-lg border border-border"
                            />
                            <button
                              onClick={() => removeAttachment(attachment.id)}
                              className="absolute -top-2 -right-2 w-5 h-5 rounded-full bg-destructive text-destructive-foreground flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                            >
                              <X className="w-3 h-3" />
                            </button>
                          </div>
                        ) : (
                          <div className="relative flex items-center gap-2 px-3 py-2 rounded-lg bg-muted/50 border border-border group">
                            {getAttachmentIcon(attachment.type)}
                            <div className="flex flex-col">
                              <span className="text-xs font-medium max-w-[120px] truncate">
                                {attachment.file.name}
                              </span>
                              <span className="text-[10px] text-muted-foreground">
                                {formatFileSize(attachment.file.size)}
                              </span>
                            </div>
                            <button
                              onClick={() => removeAttachment(attachment.id)}
                              className="ml-1 w-4 h-4 rounded-full bg-destructive/80 text-destructive-foreground flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                            >
                              <X className="w-2.5 h-2.5" />
                            </button>
                          </div>
                        )}
                      </motion.div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
            
            {/* Input Row */}
            <div className="flex gap-2">
              {/* Hidden file input */}
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                className="hidden"
                multiple
                accept="image/*,.pdf,.txt,.log,.md,.json,.xml,.nmap,.csv,.doc,.docx"
              />
              
              {/* File Upload Button */}
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={!isOnline}
                      className="shrink-0"
                    >
                      <Paperclip className="w-4 h-4" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Attach files (images, logs, documents)</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
              
              <Input
                placeholder={isOnline ? "Ask about vulnerabilities, request analysis..." : "API offline - start the backend server"}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && sendMessage()}
                className="flex-1 bg-muted/50"
                disabled={!isOnline}
              />
              <Button 
                onClick={sendMessage} 
                disabled={(!input.trim() && attachments.length === 0) || isTyping || !isOnline}
              >
                {isTyping ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              </Button>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* Context Panel - Hidden in fullscreen */}
      <div className={`w-80 ${isFullscreen ? "hidden" : "hidden lg:block"}`}>
        <GlassCard className="h-full">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              References
            </h3>
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={loadReferences}
              disabled={!isOnline}
              className="h-6 w-6 p-0"
            >
              <RefreshCw className="w-3 h-3" />
            </Button>
          </div>

          {references.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground text-sm">
              <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No references yet</p>
              <p className="text-xs mt-1">Run scans to build your knowledge base</p>
            </div>
          ) : (
            <div className="space-y-2">
              {references.map((ref) => {
                const { icon, label } = getSourceTypeInfo(ref.source_type);
                return (
                  <motion.div
                    key={ref.id}
                    whileHover={{ x: 4 }}
                    className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
                  >
                    <span className="text-lg">{icon}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{ref.title}</p>
                      <p className="text-xs text-muted-foreground">{label}</p>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}

          <div className="mt-6 pt-4 border-t border-border">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
              Analysis Context
            </h4>
            {contextStats ? (
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Documents</span>
                  <span>{contextStats.total_documents}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Recon Scans</span>
                  <span>{contextStats.recon_scans_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Enum Scans</span>
                  <span>{contextStats.enum_scans_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Knowledge Chunks</span>
                  <span>{contextStats.total_chunks}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Status</span>
                  <Badge 
                    variant="outline" 
                    className={`text-xs ${
                      contextStats.vector_store_status === 'active' 
                        ? 'text-green-500 border-green-500/50' 
                        : 'text-yellow-500 border-yellow-500/50'
                    }`}
                  >
                    {contextStats.vector_store_status}
                  </Badge>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="h-4 bg-muted/50 rounded animate-pulse" />
                <div className="h-4 bg-muted/50 rounded animate-pulse w-3/4" />
                <div className="h-4 bg-muted/50 rounded animate-pulse w-1/2" />
              </div>
            )}
          </div>
        </GlassCard>
      </div>
    </div>
  );
}