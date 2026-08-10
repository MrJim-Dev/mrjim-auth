import type { MailMessage, Mailer } from "../shared/contracts.js";

/** In-memory test mail transport; raw delivery variables never leave this inbox. */
export class FakeMailer implements Mailer {
  readonly messages: MailMessage[] = [];

  async send(message: MailMessage): Promise<void> {
    this.messages.push({
      template: message.template,
      to: message.to,
      variables: { ...message.variables },
    });
  }

  /** Returns the most recently delivered message for a template. */
  latest(template?: MailMessage["template"]): MailMessage | null {
    const messages = template === undefined
      ? this.messages
      : this.messages.filter((message) => message.template === template);
    return messages.at(-1) ?? null;
  }

  /** Removes all messages from the disposable inbox. */
  clear(): void {
    this.messages.length = 0;
  }
}
