import type { ChannelId, JsonValue } from "@dominic-nexus/shared";

export interface ChannelMessage {
  id: string;
  channelName: ChannelId;
  authorId: string;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface ChannelSendRequest {
  channelName: ChannelId;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface Channel {
  name: ChannelId;
  send(request: ChannelSendRequest): Promise<ChannelMessage>;
}
