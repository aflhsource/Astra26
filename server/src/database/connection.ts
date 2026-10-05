import mongoose from 'mongoose';
import { ExchangeModel } from '../modules/exchanges/exchange.model.js';

export async function connectDatabase(uri: string): Promise<void> {
  await mongoose.connect(uri);
  await ExchangeModel.syncIndexes();
}

export async function disconnectDatabase(): Promise<void> {
  await mongoose.disconnect();
}

export function isDatabaseConnected(): boolean {
  return mongoose.connection.readyState === 1;
}
