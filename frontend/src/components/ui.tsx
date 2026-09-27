/**
 * The app's form, overlay and disclosure controls, built on Headless UI.
 *
 * Headless UI owns behaviour and accessibility — focus trapping and focus return in
 * dialogs (UXR-7), label/description wiring inside a Field, roving keyboard focus in
 * listboxes and menus (UXR-9). It renders no styles of its own; every look comes from the
 * design tokens through the classes in app.css (UXR-1), keyed on the `data-*` state
 * attributes Headless UI sets (`data-focus`, `data-checked`, `data-open`, …).
 */
import {
  Button as HButton,
  Checkbox as HCheckbox,
  Description,
  Dialog,
  DialogBackdrop,
  DialogPanel,
  DialogTitle,
  Disclosure,
  DisclosureButton,
  DisclosurePanel,
  Field,
  Input,
  Label,
  Listbox,
  ListboxButton,
  ListboxOption,
  ListboxOptions,
  Popover,
  PopoverButton,
  PopoverPanel,
  Radio,
  RadioGroup,
  Switch as HSwitch,
  Textarea,
} from '@headlessui/react'
import type { ButtonProps as HButtonProps, InputProps as HInputProps, TextareaProps as HTextareaProps } from '@headlessui/react'
import type { ReactNode, Ref } from 'react'
import { useTranslation } from 'react-i18next'
import { IconCheck, IconChevronDown, IconChevronRight, IconHelp } from '../lib/icons'
import { buttonClass, cx } from '../lib/ui-helpers'
import type { ButtonVariant } from '../lib/ui-helpers'

type ButtonProps = Omit<HButtonProps<'button'>, 'className'> & {
  variant?: ButtonVariant
  small?: boolean
  className?: string
}

export function Button({ variant = 'secondary', small = false, className, ...props }: ButtonProps) {
  return <HButton className={cx(buttonClass(variant, small), className)} {...props} />
}

/** A labelled control. The label, hint and control are linked by Headless UI's Field. */
export function FormField({
  label,
  hint,
  className,
  children,
}: {
  label: ReactNode
  hint?: ReactNode
  className?: string
  children: ReactNode
}) {
  return (
    <Field className={cx('field', className)}>
      <Label className="field-label">{label}</Label>
      {children}
      {hint && <Description className="field-hint">{hint}</Description>}
    </Field>
  )
}

type InputProps = Omit<HInputProps<'input'>, 'className'> & { className?: string }

export function TextInput({ className, ...props }: InputProps) {
  return <Input className={cx('input', className)} {...props} />
}

type TextareaProps = Omit<HTextareaProps<'textarea'>, 'className'> & { className?: string }

export function TextArea({ className, ...props }: TextareaProps) {
  return <Textarea className={cx('input textarea', className)} {...props} />
}

export interface SelectOption<T extends string> {
  value: T
  label: ReactNode
}

/**
 * Single-choice dropdown. Put it inside a `FormField` for a visible label, or pass
 * `ariaLabel` when the surrounding UI already makes the purpose obvious.
 */
export function SelectBox<T extends string>({
  value,
  onChange,
  options,
  placeholder,
  disabled,
  ariaLabel,
  className,
}: {
  value: T
  onChange: (value: T) => void
  options: SelectOption<T>[]
  placeholder?: ReactNode
  disabled?: boolean
  ariaLabel?: string
  className?: string
}) {
  const current = options.find((option) => option.value === value)
  return (
    <Listbox value={value} onChange={onChange} disabled={disabled}>
      <ListboxButton className={cx('input select', className)} aria-label={ariaLabel}>
        <span className={current ? 'select-value' : 'select-value muted'}>
          {current?.label ?? placeholder}
        </span>
        <IconChevronDown className="select-chevron" />
      </ListboxButton>
      <ListboxOptions anchor={{ to: 'bottom start', gap: 4 }} transition className="popover-surface select-options">
        {options.map((option) => (
          <ListboxOption key={option.value} value={option.value} className="menu-item select-option">
            <IconCheck className="select-check" />
            <span>{option.label}</span>
          </ListboxOption>
        ))}
      </ListboxOptions>
    </Listbox>
  )
}

export function CheckboxField({
  checked,
  onChange,
  disabled,
  children,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  children: ReactNode
}) {
  return (
    <Field className="check-field" disabled={disabled}>
      <HCheckbox checked={checked} onChange={onChange} className="checkbox">
        <IconCheck />
      </HCheckbox>
      <Label className="check-label">{children}</Label>
    </Field>
  )
}

/** A filter pill that toggles independently of its siblings (multi-select). */
export function TogglePill({
  checked,
  onChange,
  children,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  children: ReactNode
}) {
  return (
    <HCheckbox checked={checked} onChange={onChange} className="pill">
      {children}
    </HCheckbox>
  )
}

/** A row of mutually exclusive filter pills (single-select). */
export function PillGroup<T extends string>({
  value,
  onChange,
  options,
  ariaLabel,
}: {
  value: T
  onChange: (value: T) => void
  options: SelectOption<T>[]
  ariaLabel: string
}) {
  return (
    <RadioGroup value={value} onChange={onChange} aria-label={ariaLabel} className="pill-row">
      {options.map((option) => (
        <Radio key={option.value} value={option.value} className="pill">
          {option.label}
        </Radio>
      ))}
    </RadioGroup>
  )
}

export function SwitchField({
  checked,
  onChange,
  disabled,
  children,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  children: ReactNode
}) {
  return (
    <Field className="switch-field" disabled={disabled}>
      <HSwitch checked={checked} onChange={onChange} className="switch">
        <span className="switch-thumb" />
      </HSwitch>
      <Label className="switch-label">{children}</Label>
    </Field>
  )
}

/**
 * One collapsible row in a `.disclosure-group`. The trigger sits in a heading so the
 * page outline stays navigable by screen-reader heading shortcuts.
 */
export function DisclosureRow({
  title,
  summary,
  defaultOpen,
  children,
}: {
  title: ReactNode
  summary?: ReactNode
  defaultOpen?: boolean
  children: ReactNode
}) {
  return (
    <Disclosure as="section" className="disclosure" defaultOpen={defaultOpen}>
      <h2 className="disclosure-heading">
        <DisclosureButton className="disclosure-button">
          <span className="disclosure-title">{title}</span>
          {summary && <span className="disclosure-summary">{summary}</span>}
          <IconChevronRight className="disclosure-chevron" />
        </DisclosureButton>
      </h2>
      <DisclosurePanel className="disclosure-panel">{children}</DisclosurePanel>
    </Disclosure>
  )
}

/** Modal dialog. Headless UI traps focus inside and returns it to the trigger on close. */
export function Modal({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean
  onClose: () => void
  title: ReactNode
  description?: ReactNode
  children: ReactNode
}) {
  return (
    <Dialog open={open} onClose={onClose} className="modal-root">
      <DialogBackdrop transition className="modal-backdrop" />
      <div className="modal-wrap">
        <DialogPanel transition className="modal-panel">
          <DialogTitle className="modal-title">{title}</DialogTitle>
          {description && <Description className="modal-description">{description}</Description>}
          {children}
        </DialogPanel>
      </div>
    </Dialog>
  )
}

/** Replaces `window.confirm` for destructive actions, so the prompt is keyboard-safe and themed. */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel,
  pending,
}: {
  open: boolean
  onClose: () => void
  onConfirm: () => void
  title: ReactNode
  description?: ReactNode
  confirmLabel: ReactNode
  pending?: boolean
}) {
  const { t } = useTranslation()
  return (
    <Modal open={open} onClose={onClose} title={title} description={description}>
      <div className="modal-actions">
        <Button onClick={onClose}>{t('common.cancel')}</Button>
        <Button variant="danger" onClick={onConfirm} disabled={pending}>
          {pending ? t('common.saving') : confirmLabel}
        </Button>
      </div>
    </Modal>
  )
}

/** A small "?" that opens a plain-language explanation of a technical term. */
export function InfoTip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Popover className="infotip">
      <PopoverButton className="infotip-button" aria-label={label}>
        <IconHelp />
      </PopoverButton>
      <PopoverPanel anchor={{ to: 'bottom', gap: 6 }} transition className="popover-surface infotip-panel">
        {children}
      </PopoverPanel>
    </Popover>
  )
}

/** Error summary that the caller focuses on a failed submit (UXR-7). */
export function ErrorSummary({
  ref,
  title,
  message,
}: {
  ref?: Ref<HTMLDivElement>
  title: string
  message: ReactNode
}) {
  return (
    <div className="error-summary" role="alert" tabIndex={-1} ref={ref}>
      <p>{title}</p>
      <ul>
        <li>{message}</li>
      </ul>
    </div>
  )
}
