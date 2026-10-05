import { SourceModel, type SourceDocument } from './source.model.js';
import type { CreateSourceInput, SourceStatus } from './source.types.js';

export async function insertSource(input: CreateSourceInput): Promise<SourceDocument> {
  return SourceModel.create(input);
}

export async function findSourceById(sourceId: string): Promise<SourceDocument | null> {
  return SourceModel.findOne({ sourceId }).exec();
}

export async function findSources(): Promise<SourceDocument[]> {
  return SourceModel.find().sort({ sourceId: 1 }).exec();
}

export async function changeSourceStatus(
  sourceId: string,
  status: SourceStatus,
): Promise<SourceDocument | null> {
  return SourceModel.findOneAndUpdate(
    { sourceId },
    { $set: { status } },
    { returnDocument: 'after', runValidators: true },
  ).exec();
}

export async function upsertSource(input: CreateSourceInput): Promise<SourceDocument> {
  return SourceModel.findOneAndUpdate(
    { sourceId: input.sourceId },
    { $set: input },
    {
      returnDocument: 'after',
      upsert: true,
      runValidators: true,
      setDefaultsOnInsert: true,
    },
  ).exec() as Promise<SourceDocument>;
}
