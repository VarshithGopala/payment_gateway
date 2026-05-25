import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export class JsonStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.paymentsPath = join(dataDir, 'payments.json');
    this.eventsPath = join(dataDir, 'stripe-events.json');
    this.queue = Promise.resolve();
  }

  async init() {
    await mkdir(this.dataDir, { recursive: true });
    await this.ensureFile(this.paymentsPath, { payments: [] });
    await this.ensureFile(this.eventsPath, { events: [] });
  }

  async ensureFile(path, fallback) {
    try {
      await readFile(path, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
      await this.writeJson(path, fallback);
    }
  }

  async withLock(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  async readJson(path, fallback) {
    try {
      return JSON.parse(await readFile(path, 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') {
        return fallback;
      }
      throw error;
    }
  }

  async writeJson(path, value) {
    const tempPath = `${path}.${Date.now()}.tmp`;
    await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await rename(tempPath, path);
  }

  async findPaymentBySiteOrder(siteId, orderId) {
    const data = await this.readJson(this.paymentsPath, { payments: [] });
    return data.payments.find((payment) => payment.siteId === siteId && payment.orderId === orderId) || null;
  }

  async getPayment(paymentId) {
    const data = await this.readJson(this.paymentsPath, { payments: [] });
    return data.payments.find((payment) => payment.id === paymentId) || null;
  }

  async getPaymentByStripeSession(sessionId) {
    const data = await this.readJson(this.paymentsPath, { payments: [] });
    return data.payments.find((payment) => payment.stripeCheckoutSessionId === sessionId) || null;
  }

  async getPaymentByRazorpayOrder(orderId) {
    const data = await this.readJson(this.paymentsPath, { payments: [] });
    return data.payments.find((payment) => payment.razorpayOrderId === orderId) || null;
  }

  async getPaymentByRazorpayPayment(paymentId) {
    const data = await this.readJson(this.paymentsPath, { payments: [] });
    return data.payments.find((payment) => payment.razorpayPaymentId === paymentId) || null;
  }

  async createPayment(payment) {
    return this.withLock(async () => {
      const data = await this.readJson(this.paymentsPath, { payments: [] });
      data.payments.push(payment);
      await this.writeJson(this.paymentsPath, data);
      return payment;
    });
  }

  async updatePayment(paymentId, updater) {
    return this.withLock(async () => {
      const data = await this.readJson(this.paymentsPath, { payments: [] });
      const index = data.payments.findIndex((payment) => payment.id === paymentId);
      if (index === -1) {
        return null;
      }

      const current = data.payments[index];
      const next = {
        ...current,
        ...updater(current),
        updatedAt: new Date().toISOString(),
      };
      data.payments[index] = next;
      await this.writeJson(this.paymentsPath, data);
      return next;
    });
  }

  async markStripeEvent(event) {
    return this.withLock(async () => {
      const data = await this.readJson(this.eventsPath, { events: [] });
      const existing = data.events.find((storedEvent) => storedEvent.id === event.id);
      if (existing) {
        return false;
      }

      data.events.push({
        id: event.id,
        type: event.type,
        createdAt: new Date().toISOString(),
      });
      await this.writeJson(this.eventsPath, data);
      return true;
    });
  }
}
