import { Check, ChevronDown } from "lucide-react";
import { Select as Primitive } from "radix-ui";
import { cloneElement, isValidElement, useEffect, useId, useRef, useState, type ComponentProps, type InputHTMLAttributes, type ReactNode } from "react";

import { cn } from "./cn";

const control =
  "h-9 w-full min-w-0 rounded-md border border-border bg-surface px-3 text-sm text-fg shadow-xs placeholder:text-fg-3 " +
  "transition-[border-color,box-shadow] hover:border-border-strong focus:border-accent focus:outline-hidden " +
  "focus:ring-3 focus:ring-accent/15 disabled:opacity-60 aria-[invalid=true]:border-bad";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(control, className)} {...props} />;
}

// A filter typed into a list kept in the address: the value leaves the field
// once typing pauses, so the list asks the server once per pause instead of
// once per key. A value changed from outside (back button, a saved view) shows
// up in the field.
export function FilterInput({
  value,
  onValueChange,
  delay = 300,
  ...props
}: { value: string; onValueChange: (value: string) => void; delay?: number } & Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  const [text, setText] = useState(value);
  // The value this field sent last: its echo from the address must not
  // overwrite what was typed since.
  const sent = useRef(value);
  useEffect(() => {
    if (value === sent.current) return;
    sent.current = value;
    setText(value);
  }, [value]);
  useEffect(() => {
    if (text === sent.current) return;
    const timer = setTimeout(() => {
      sent.current = text;
      onValueChange(text);
    }, delay);
    return () => clearTimeout(timer);
  }, [text, delay, onValueChange]);
  return <Input {...props} value={text} onChange={(event) => setText(event.target.value)} />;
}

export interface Option {
  value: string;
  label: ReactNode;
  hint?: ReactNode;
}

// Radix reserves the empty string for "nothing chosen", but filters use it for
// "all". The empty option travels under this name inside the component only.
const emptyValue = "\u0000all";

// A select with its own list: readable options with hints and a check on the
// chosen one, the same in every browser, keyboard and screen reader included.
export function Select({
  value,
  onValueChange,
  options,
  placeholder,
  disabled,
  className,
  "aria-label": label,
  "aria-describedby": describedBy,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: Option[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  "aria-label"?: string;
  "aria-describedby"?: string;
}) {
  const encode = (raw: string) => (raw === "" ? emptyValue : raw);
  return (
    <Primitive.Root value={encode(value)} onValueChange={(next) => onValueChange(next === emptyValue ? "" : next)} disabled={disabled}>
      <Primitive.Trigger
        aria-label={label}
        aria-describedby={describedBy}
        className={cn(control, "inline-flex cursor-pointer items-center justify-between gap-2 text-left data-[placeholder]:text-fg-3", className)}
      >
        <span className="min-w-0 truncate"><Primitive.Value placeholder={placeholder} /></span>
        <Primitive.Icon asChild>
          <ChevronDown aria-hidden className="size-4 shrink-0 text-fg-3" />
        </Primitive.Icon>
      </Primitive.Trigger>
      <Primitive.Portal>
        <Primitive.Content
          position="popper"
          sideOffset={4}
          className="z-[70] max-h-[min(22rem,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-lg border border-border bg-surface p-1 shadow-raised"
        >
          <Primitive.Viewport>
            {options.map((option) => (
              <Primitive.Item
                key={encode(option.value)}
                value={encode(option.value)}
                className="relative flex cursor-pointer flex-col rounded-md py-2 pr-3 pl-8 text-sm text-fg outline-hidden select-none data-[disabled]:opacity-50 data-[highlighted]:bg-surface-2"
              >
                <Primitive.ItemIndicator className="absolute top-2.5 left-2.5">
                  <Check className="size-4 text-accent" />
                </Primitive.ItemIndicator>
                <Primitive.ItemText>{option.label}</Primitive.ItemText>
                {option.hint && <span className="text-xs text-fg-3">{option.hint}</span>}
              </Primitive.Item>
            ))}
          </Primitive.Viewport>
        </Primitive.Content>
      </Primitive.Portal>
    </Primitive.Root>
  );
}

export function Checkbox({ className, ...props }: Omit<ComponentProps<"input">, "type">) {
  return <input type="checkbox" className={cn("size-4 cursor-pointer rounded accent-[var(--accent)]", className)} {...props} />;
}

// The width of a filter above a list: two to a row on a phone, one fixed
// width on a wider screen.
export const filterField = "min-w-36 flex-1 sm:w-48 sm:flex-none";

// A labelled control. The label wraps the control, so clicking it focuses the
// control; the hint sits outside the label so the control's name stays just
// the label, and the hint is announced as its description.
export function Field({ label, hint, error, className, children }: { label: string; hint?: ReactNode; error?: string; className?: string; children: ReactNode }) {
  const describedBy = useId();
  const note = error ?? hint;
  const labelled = note && isValidElement<{ "aria-describedby"?: string }>(children) ? cloneElement(children, { "aria-describedby": describedBy }) : children;
  return (
    <div className={cn("flex min-w-0 flex-col gap-1.5", className)}>
      <label className="flex min-w-0 flex-col gap-1.5">
        <span className="text-xs font-medium text-fg-2">{label}</span>
        {labelled}
      </label>
      {note && <span id={describedBy} className={cn("text-xs", error ? "text-bad" : "text-fg-3")}>{note}</span>}
    </div>
  );
}

export function CheckField({ label, className, ...props }: { label: string } & Omit<InputHTMLAttributes<HTMLInputElement>, "type">) {
  return (
    <label className={cn("inline-flex h-9 cursor-pointer items-center gap-2 text-sm text-fg-2", className)}>
      <Checkbox {...props} />
      {label}
    </label>
  );
}
