package com.tracepcap.monitor.dto;

/** How many devices a network has in total, with irregularities, and with a private MAC (#918). */
public record NetworkDeviceCountsDto(long all, long irregular, long privateMac) {}
