/** Minimal shape of the props Recharts passes to a custom tooltip. */
export interface RechartsTooltipProps<T> {
  active?: boolean;
  payload?: ReadonlyArray<{ payload?: T }>;
}

export function payloadOf<T>(props: RechartsTooltipProps<T>): T | undefined {
  return props.active ? props.payload?.[0]?.payload : undefined;
}
