/*
 * Copyright (c) 2026 HomoXterm contributors.
 * Licensed under the Apache License, Version 2.0.
 */

export interface RemoteMetricsPort {
  readonly metricsEpoch?: number;
  collectRemoteMetrics(): Promise<string>;
}
