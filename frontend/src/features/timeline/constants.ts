/** Interval (seconds) passed to the backend when granularity is set to "auto". */
export const AUTO_GRANULARITY_INTERVAL = 1;

/**
 * Target bucket count passed to the backend when granularity is set to "auto".
 * The backend auto-adjusts the interval so the response contains at most this
 * many data points, giving a clean ~100-bin view of the capture duration.
 */
export const AUTO_GRANULARITY_MAX_DATAPOINTS = 100;
