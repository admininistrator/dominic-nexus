import type { JsonValue } from "@dominic-nexus/shared";

export interface ChannelMessage {
  id: string;
  channelName: string;
  authorId: string;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface ChannelSendRequest {
  channelName: string;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface Channel {
  name: string;
  send(request: ChannelSendRequest): Promise<ChannelMessage>;
}
