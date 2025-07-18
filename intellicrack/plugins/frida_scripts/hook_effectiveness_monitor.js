/*
 * This file is part of Intellicrack.
 * Copyright (C) 2025 Zachary Flint
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Hook Effectiveness Measurement and Reporting System
 * 
 * Comprehensive monitoring and reporting system that measures the effectiveness
 * of installed hooks, tracks success rates, and provides detailed analytics
 * for optimization and performance tuning of bypass techniques.
 * 
 * Author: Intellicrack Framework
 * Version: 2.0.0
 * License: GPL v3
 */

{
    name: "Hook Effectiveness Monitor",
    description: "Comprehensive hook effectiveness measurement and reporting system",
    version: "2.0.0",
    
    // Configuration for effectiveness monitoring
    config: {
        // Monitoring settings
        monitoring: {
            enabled: true,
            realTimeTracking: true,
            detailedLogging: true,
            performanceMetrics: true,
            successRateTracking: true,
            failureAnalysis: true,
            adaptiveOptimization: true,
            reportGeneration: true
        },
        
        // Measurement categories
        categories: {
            hookInstallation: true,
            hookExecution: true,
            bypassSuccess: true,
            protectionDetection: true,
            performanceImpact: true,
            resourceUsage: true,
            stabilityMetrics: true,
            compatibilityMetrics: true
        },
        
        // Reporting configuration
        reporting: {
            enableRealtimeReports: true,
            enablePeriodicReports: true,
            enableSummaryReports: true,
            enableDetailedAnalysis: true,
            reportInterval: 60000, // 1 minute
            summaryInterval: 300000, // 5 minutes
            detailedInterval: 900000, // 15 minutes
            retentionPeriod: 3600000 // 1 hour
        },
        
        // Performance thresholds
        thresholds: {
            minSuccessRate: 0.8, // 80%
            maxResponseTime: 100, // ms
            maxCpuUsage: 10, // %
            maxMemoryUsage: 50, // MB
            maxHookInstallTime: 50, // ms
            minStabilityScore: 0.9 // 90%
        },
        
        // Analysis settings
        analysis: {
            enableTrendAnalysis: true,
            enableCorrelationAnalysis: true,
            enablePredictiveAnalysis: true,
            enableAnomalyDetection: true,
            trendWindow: 300000, // 5 minutes
            correlationThreshold: 0.7,
            anomalyThreshold: 0.3
        }
    },
    
    // Effectiveness monitoring state
    monitor: {
        isRunning: false,
        startTime: 0,
        totalHooks: 0,
        activeHooks: new Map(),
        hookHistory: new Map(),
        measurementData: new Map(),
        reportQueue: []
    },
    
    // Hook performance metrics
    metrics: {
        installation: new Map(),
        execution: new Map(),
        success: new Map(),
        failure: new Map(),
        performance: new Map(),
        stability: new Map(),
        resource: new Map()
    },
    
    // Effectiveness statistics
    statistics: {
        totalMeasurements: 0,
        totalHooksMonitored: 0,
        averageSuccessRate: 0.0,
        averageResponseTime: 0.0,
        totalBypassAttempts: 0,
        successfulBypasses: 0,
        failedBypasses: 0,
        stabilityScore: 0.0,
        performanceScore: 0.0,
        overallEffectiveness: 0.0
    },
    
    // Reporting data structures
    reports: {
        realtime: {},
        periodic: [],
        summary: {},
        detailed: {},
        trends: {},
        correlations: {},
        predictions: {},
        anomalies: []
    },
    
    onAttach: function(pid) {
        send({
            type: "info",
            target: "hook_effectiveness_monitor",
            action: "attaching_to_process",
            process_id: pid
        });
        this.processId = pid;
        this.monitor.startTime = Date.now();
    },
    
    run: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "starting_monitoring_system"
        });
        
        // Initialize monitoring components
        this.initializeMonitoring();
        this.setupHookTracking();
        this.startMetricsCollection();
        this.startReporting();
        this.setupAnalysisEngine();
        
        this.installSummary();
    },
    
    // === MONITORING INITIALIZATION ===
    initializeMonitoring: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "initializing_monitoring"
        });
        
        this.monitor.isRunning = true;
        this.monitor.startTime = Date.now();
        
        // Clear monitoring data
        this.monitor.activeHooks.clear();
        this.monitor.hookHistory.clear();
        this.monitor.measurementData.clear();
        this.monitor.reportQueue = [];
        
        // Initialize metrics maps
        this.metrics.installation.clear();
        this.metrics.execution.clear();
        this.metrics.success.clear();
        this.metrics.failure.clear();
        this.metrics.performance.clear();
        this.metrics.stability.clear();
        this.metrics.resource.clear();
        
        // Reset statistics
        this.resetStatistics();
        
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "monitoring_system_initialized"
        });
    },
    
    resetStatistics: function() {
        this.statistics.totalMeasurements = 0;
        this.statistics.totalHooksMonitored = 0;
        this.statistics.averageSuccessRate = 0.0;
        this.statistics.averageResponseTime = 0.0;
        this.statistics.totalBypassAttempts = 0;
        this.statistics.successfulBypasses = 0;
        this.statistics.failedBypasses = 0;
        this.statistics.stabilityScore = 0.0;
        this.statistics.performanceScore = 0.0;
        this.statistics.overallEffectiveness = 0.0;
    },
    
    // === HOOK TRACKING SETUP ===
    setupHookTracking: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "setting_up_hook_tracking"
        });
        
        // Monitor Frida's hook installation
        this.setupHookInstallationTracking();
        
        // Monitor hook execution
        this.setupHookExecutionTracking();
        
        // Monitor bypass attempts
        this.setupBypassTracking();
        
        // Monitor performance impact
        this.setupPerformanceTracking();
        
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "hook_tracking_configured"
        });
    },
    
    setupHookInstallationTracking: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "setting_up_hook_installation_tracking"
        });
        
        // Track when hooks are installed
        var originalInterceptorAttach = Interceptor.attach;
        var self = this;
        
        Interceptor.attach = function(target, callbacks) {
            var installStart = Date.now();
            
            try {
                var result = originalInterceptorAttach.call(this, target, callbacks);
                var installTime = Date.now() - installStart;
                
                // Record successful hook installation
                self.recordHookInstallation(target, true, installTime, callbacks);
                
                return result;
            } catch(e) {
                var installTime = Date.now() - installStart;
                
                // Record failed hook installation
                self.recordHookInstallation(target, false, installTime, callbacks, e);
                
                throw e;
            }
        };
        
        // Track when hooks are replaced
        var originalInterceptorReplace = Interceptor.replace;
        
        Interceptor.replace = function(target, replacement) {
            var replaceStart = Date.now();
            
            try {
                var result = originalInterceptorReplace.call(this, target, replacement);
                var replaceTime = Date.now() - replaceStart;
                
                // Record successful hook replacement
                self.recordHookReplacement(target, true, replaceTime, replacement);
                
                return result;
            } catch(e) {
                var replaceTime = Date.now() - replaceStart;
                
                // Record failed hook replacement
                self.recordHookReplacement(target, false, replaceTime, replacement, e);
                
                throw e;
            }
        };
    },
    
    setupHookExecutionTracking: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "setting_up_hook_execution_tracking"
        });
        
        // This will be used to wrap hook callbacks to measure execution
        this.wrapHookCallbacks = function(originalCallbacks, hookId) {
            var wrappedCallbacks = {};
            var self = this;
            
            if (originalCallbacks.onEnter) {
                wrappedCallbacks.onEnter = function(args) {
                    var executionStart = Date.now();
                    this.hookId = hookId;
                    this.executionStart = executionStart;
                    
                    try {
                        var result = originalCallbacks.onEnter.call(this, args);
                        self.recordHookExecution(hookId, "onEnter", true, Date.now() - executionStart);
                        return result;
                    } catch(e) {
                        self.recordHookExecution(hookId, "onEnter", false, Date.now() - executionStart, e);
                        throw e;
                    }
                };
            }
            
            if (originalCallbacks.onLeave) {
                wrappedCallbacks.onLeave = function(retval) {
                    var executionStart = Date.now();
                    
                    try {
                        var result = originalCallbacks.onLeave.call(this, retval);
                        self.recordHookExecution(this.hookId, "onLeave", true, Date.now() - executionStart);
                        return result;
                    } catch(e) {
                        self.recordHookExecution(this.hookId, "onLeave", false, Date.now() - executionStart, e);
                        throw e;
                    }
                };
            }
            
            return wrappedCallbacks;
        }.bind(this);
    },
    
    setupBypassTracking: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "setting_up_bypass_tracking"
        });
        
        // Track bypass attempts and their success/failure
        this.trackBypassAttempt = function(technique, success, details) {
            this.statistics.totalBypassAttempts++;
            
            if (success) {
                this.statistics.successfulBypasses++;
                this.recordBypassSuccess(technique, details);
            } else {
                this.statistics.failedBypasses++;
                this.recordBypassFailure(technique, details);
            }
            
            this.updateSuccessRate();
        }.bind(this);
    },
    
    setupPerformanceTracking: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "setting_up_performance_tracking"
        });
        
        // Monitor CPU and memory usage
        setInterval(() => {
            this.measurePerformanceImpact();
        }, 5000); // Every 5 seconds
    },
    
    // === METRICS COLLECTION ===
    startMetricsCollection: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "starting_metrics_collection"
        });
        
        // Start continuous metrics collection
        setInterval(() => {
            this.collectMetrics();
        }, 1000); // Every second
        
        // Update statistics periodically
        setInterval(() => {
            this.updateStatistics();
        }, 10000); // Every 10 seconds
        
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "metrics_collection_started"
        });
    },
    
    collectMetrics: function() {
        if (!this.monitor.isRunning) return;
        
        try {
            var timestamp = Date.now();
            
            // Collect hook metrics
            this.collectHookMetrics(timestamp);
            
            // Collect performance metrics
            this.collectPerformanceMetrics(timestamp);
            
            // Collect stability metrics
            this.collectStabilityMetrics(timestamp);
            
            // Collect resource usage metrics
            this.collectResourceMetrics(timestamp);
            
            this.statistics.totalMeasurements++;
            
        } catch(e) {
            send({
                type: "error",
                target: "hook_effectiveness_monitor",
                action: "metrics_collection_error",
                error: e.toString()
            });
        }
    },
    
    collectHookMetrics: function(timestamp) {
        // Collect metrics for all active hooks
        this.monitor.activeHooks.forEach((hookData, hookId) => {
            var metrics = {
                timestamp: timestamp,
                hookId: hookId,
                executionCount: hookData.executionCount || 0,
                successCount: hookData.successCount || 0,
                failureCount: hookData.failureCount || 0,
                averageExecutionTime: hookData.averageExecutionTime || 0,
                isActive: hookData.isActive || false,
                installTime: hookData.installTime || 0
            };
            
            this.metrics.execution.set(hookId + "_" + timestamp, metrics);
        });
    },
    
    collectPerformanceMetrics: function(timestamp) {
        var performanceData = {
            timestamp: timestamp,
            cpuUsage: this.estimateCpuUsage(),
            memoryUsage: this.estimateMemoryUsage(),
            hookCount: this.monitor.activeHooks.size,
            averageResponseTime: this.calculateAverageResponseTime(),
            throughput: this.calculateThroughput()
        };
        
        this.metrics.performance.set(timestamp, performanceData);
    },
    
    collectStabilityMetrics: function(timestamp) {
        var stabilityData = {
            timestamp: timestamp,
            crashCount: this.getCrashCount(),
            exceptionCount: this.getExceptionCount(),
            hookFailures: this.getHookFailureCount(),
            uptime: timestamp - this.monitor.startTime,
            stabilityScore: this.calculateStabilityScore()
        };
        
        this.metrics.stability.set(timestamp, stabilityData);
    },
    
    collectResourceMetrics: function(timestamp) {
        var resourceData = {
            timestamp: timestamp,
            memoryFootprint: this.calculateMemoryFootprint(),
            cpuTime: this.calculateCpuTime(),
            hookOverhead: this.calculateHookOverhead(),
            networkUsage: this.calculateNetworkUsage()
        };
        
        this.metrics.resource.set(timestamp, resourceData);
    },
    
    // === HOOK RECORDING METHODS ===
    recordHookInstallation: function(target, success, installTime, callbacks, error) {
        var hookId = this.generateHookId(target);
        var timestamp = Date.now();
        
        var installData = {
            hookId: hookId,
            target: target.toString(),
            success: success,
            installTime: installTime,
            timestamp: timestamp,
            callbacks: callbacks,
            error: error || null
        };
        
        this.metrics.installation.set(hookId, installData);
        
        if (success) {
            // Track active hook
            this.monitor.activeHooks.set(hookId, {
                target: target,
                installTime: installTime,
                installTimestamp: timestamp,
                executionCount: 0,
                successCount: 0,
                failureCount: 0,
                averageExecutionTime: 0,
                isActive: true,
                callbacks: callbacks
            });
            
            this.monitor.totalHooks++;
            send({
                type: "success",
                target: "hook_effectiveness_monitor",
                action: "hook_installed",
                hook_id: hookId,
                install_time: installTime
            });
        } else {
            send({
                type: "error",
                target: "hook_effectiveness_monitor",
                action: "hook_installation_failed",
                hook_id: hookId,
                error: error.toString()
            });
        }
    },
    
    recordHookReplacement: function(target, success, replaceTime, replacement, error) {
        var hookId = this.generateHookId(target);
        var timestamp = Date.now();
        
        var replaceData = {
            hookId: hookId,
            target: target.toString(),
            success: success,
            replaceTime: replaceTime,
            timestamp: timestamp,
            replacement: replacement,
            error: error || null
        };
        
        this.metrics.installation.set(hookId + "_replace", replaceData);
        
        if (success) {
            send({
                type: "success",
                target: "hook_effectiveness_monitor",
                action: "hook_replaced",
                hook_id: hookId,
                replace_time: replaceTime
            });
        } else {
            send({
                type: "error",
                target: "hook_effectiveness_monitor",
                action: "hook_replacement_failed",
                hook_id: hookId,
                error: error.toString()
            });
        }
    },
    
    recordHookExecution: function(hookId, phase, success, executionTime, error) {
        var hookData = this.monitor.activeHooks.get(hookId);
        if (!hookData) return;
        
        hookData.executionCount++;
        
        if (success) {
            hookData.successCount++;
        } else {
            hookData.failureCount++;
        }
        
        // Update average execution time
        var totalTime = hookData.averageExecutionTime * (hookData.executionCount - 1) + executionTime;
        hookData.averageExecutionTime = totalTime / hookData.executionCount;
        
        // Record execution metrics
        var executionData = {
            hookId: hookId,
            phase: phase,
            success: success,
            executionTime: executionTime,
            timestamp: Date.now(),
            error: error || null
        };
        
        var executionKey = hookId + "_" + Date.now() + "_" + phase;
        this.metrics.execution.set(executionKey, executionData);
        
        if (!success && error) {
            send({
                type: "error",
                target: "hook_effectiveness_monitor",
                action: "hook_execution_failed",
                hook_id: hookId,
                phase: phase,
                error: error.toString()
            });
        }
    },
    
    recordBypassSuccess: function(technique, details) {
        var successData = {
            technique: technique,
            timestamp: Date.now(),
            details: details,
            success: true
        };
        
        var successKey = technique + "_" + Date.now();
        this.metrics.success.set(successKey, successData);
        
        send({
            type: "bypass",
            target: "hook_effectiveness_monitor",
            action: "bypass_success",
            technique: technique,
            details: details
        });
    },
    
    recordBypassFailure: function(technique, details) {
        var failureData = {
            technique: technique,
            timestamp: Date.now(),
            details: details,
            success: false
        };
        
        var failureKey = technique + "_" + Date.now();
        this.metrics.failure.set(failureKey, failureData);
        
        send({
            type: "error",
            target: "hook_effectiveness_monitor",
            action: "bypass_failure",
            technique: technique,
            details: details
        });
    },
    
    // === STATISTICS CALCULATION ===
    updateStatistics: function() {
        try {
            this.calculateAverageSuccessRate();
            this.calculateAverageResponseTime();
            this.calculateStabilityScore();
            this.calculatePerformanceScore();
            this.calculateOverallEffectiveness();
            
            this.statistics.totalHooksMonitored = this.monitor.activeHooks.size;
            
        } catch(e) {
            send({
                type: "error",
                target: "hook_effectiveness_monitor",
                action: "statistics_update_error",
                error: e.toString()
            });
        }
    },
    
    calculateAverageSuccessRate: function() {
        var totalSuccess = 0;
        var totalAttempts = 0;
        
        this.monitor.activeHooks.forEach((hookData) => {
            totalSuccess += hookData.successCount;
            totalAttempts += hookData.executionCount;
        });
        
        this.statistics.averageSuccessRate = totalAttempts > 0 ? totalSuccess / totalAttempts : 0;
    },
    
    calculateAverageResponseTime: function() {
        var totalTime = 0;
        var hookCount = 0;
        
        this.monitor.activeHooks.forEach((hookData) => {
            if (hookData.averageExecutionTime > 0) {
                totalTime += hookData.averageExecutionTime;
                hookCount++;
            }
        });
        
        this.statistics.averageResponseTime = hookCount > 0 ? totalTime / hookCount : 0;
        return this.statistics.averageResponseTime;
    },
    
    calculateStabilityScore: function() {
        var totalExecutions = 0;
        var totalFailures = 0;
        
        this.monitor.activeHooks.forEach((hookData) => {
            totalExecutions += hookData.executionCount;
            totalFailures += hookData.failureCount;
        });
        
        this.statistics.stabilityScore = totalExecutions > 0 ? 
            1.0 - (totalFailures / totalExecutions) : 1.0;
        
        return this.statistics.stabilityScore;
    },
    
    calculatePerformanceScore: function() {
        var responseTimeScore = this.statistics.averageResponseTime < this.config.thresholds.maxResponseTime ? 1.0 :
            Math.max(0, 1.0 - (this.statistics.averageResponseTime - this.config.thresholds.maxResponseTime) / 100);
        
        var cpuUsageScore = this.estimateCpuUsage() < this.config.thresholds.maxCpuUsage ? 1.0 :
            Math.max(0, 1.0 - (this.estimateCpuUsage() - this.config.thresholds.maxCpuUsage) / 10);
        
        var memoryUsageScore = this.estimateMemoryUsage() < this.config.thresholds.maxMemoryUsage ? 1.0 :
            Math.max(0, 1.0 - (this.estimateMemoryUsage() - this.config.thresholds.maxMemoryUsage) / 50);
        
        this.statistics.performanceScore = (responseTimeScore + cpuUsageScore + memoryUsageScore) / 3;
        return this.statistics.performanceScore;
    },
    
    calculateOverallEffectiveness: function() {
        var successRateWeight = 0.4;
        var stabilityWeight = 0.3;
        var performanceWeight = 0.2;
        var bypassWeight = 0.1;
        
        var bypassScore = this.statistics.totalBypassAttempts > 0 ?
            this.statistics.successfulBypasses / this.statistics.totalBypassAttempts : 0;
        
        this.statistics.overallEffectiveness = 
            (this.statistics.averageSuccessRate * successRateWeight) +
            (this.statistics.stabilityScore * stabilityWeight) +
            (this.statistics.performanceScore * performanceWeight) +
            (bypassScore * bypassWeight);
        
        return this.statistics.overallEffectiveness;
    },
    
    updateSuccessRate: function() {
        this.calculateAverageSuccessRate();
    },
    
    // === PERFORMANCE MEASUREMENT ===
    measurePerformanceImpact: function() {
        try {
            var currentMetrics = {
                timestamp: Date.now(),
                cpuUsage: this.estimateCpuUsage(),
                memoryUsage: this.estimateMemoryUsage(),
                hookCount: this.monitor.activeHooks.size,
                activeProcesses: this.getActiveProcessCount()
            };
            
            this.recordPerformanceImpact(currentMetrics);
            
        } catch(e) {
            send({
                type: "error",
                target: "hook_effectiveness_monitor",
                action: "performance_measurement_error",
                error: e.toString()
            });
        }
    },
    
    recordPerformanceImpact: function(metrics) {
        var impactKey = "perf_" + metrics.timestamp;
        this.metrics.performance.set(impactKey, metrics);
        
        // Check for performance issues
        if (metrics.cpuUsage > this.config.thresholds.maxCpuUsage) {
            send({
                type: "warning",
                target: "hook_effectiveness_monitor",
                action: "high_cpu_usage",
                cpu_usage: metrics.cpuUsage,
                threshold: this.config.thresholds.maxCpuUsage
            });
        }
        
        if (metrics.memoryUsage > this.config.thresholds.maxMemoryUsage) {
            send({
                type: "warning",
                target: "hook_effectiveness_monitor",
                action: "high_memory_usage",
                memory_usage: metrics.memoryUsage,
                threshold: this.config.thresholds.maxMemoryUsage
            });
        }
    },
    
    estimateCpuUsage: function() {
        // Simplified CPU usage estimation based on hook activity
        var activeHooks = this.monitor.activeHooks.size;
        var executionRate = this.calculateExecutionRate();
        
        return Math.min(100, (activeHooks * 0.5) + (executionRate * 0.1));
    },
    
    estimateMemoryUsage: function() {
        // Simplified memory usage estimation
        var activeHooks = this.monitor.activeHooks.size;
        var metricsSize = this.getMetricsStorageSize();
        
        return (activeHooks * 0.1) + (metricsSize / 1024 / 1024); // MB
    },
    
    calculateExecutionRate: function() {
        var currentTime = Date.now();
        var timeWindow = 10000; // 10 seconds
        var executionCount = 0;
        
        this.monitor.activeHooks.forEach((hookData) => {
            // Estimate executions in the last time window
            if (hookData.executionCount > 0) {
                var timeSinceInstall = currentTime - hookData.installTimestamp;
                var rate = hookData.executionCount / timeSinceInstall * timeWindow;
                executionCount += rate;
            }
        });
        
        return executionCount;
    },
    
    getMetricsStorageSize: function() {
        // Estimate memory used by metrics storage
        var totalEntries = 
            this.metrics.installation.size +
            this.metrics.execution.size +
            this.metrics.success.size +
            this.metrics.failure.size +
            this.metrics.performance.size +
            this.metrics.stability.size +
            this.metrics.resource.size;
        
        return totalEntries * 500; // Estimated 500 bytes per entry
    },
    
    // === REPORTING SYSTEM ===
    startReporting: function() {
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "starting_reporting_system"
        });
        
        // Start real-time reporting
        if (this.config.reporting.enableRealtimeReports) {
            this.startRealtimeReporting();
        }
        
        // Start periodic reporting
        if (this.config.reporting.enablePeriodicReports) {
            this.startPeriodicReporting();
        }
        
        // Start summary reporting
        if (this.config.reporting.enableSummaryReports) {
            this.startSummaryReporting();
        }
        
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "reporting_system_started"
        });
    },
    
    startRealtimeReporting: function() {
        setInterval(() => {
            this.generateRealtimeReport();
        }, this.config.reporting.reportInterval);
    },
    
    startPeriodicReporting: function() {
        setInterval(() => {
            this.generatePeriodicReport();
        }, this.config.reporting.summaryInterval);
    },
    
    startSummaryReporting: function() {
        setInterval(() => {
            this.generateSummaryReport();
        }, this.config.reporting.detailedInterval);
    },
    
    generateRealtimeReport: function() {
        var report = {
            timestamp: Date.now(),
            type: "realtime",
            statistics: Object.assign({}, this.statistics),
            activeHooks: this.monitor.activeHooks.size,
            currentPerformance: {
                cpuUsage: this.estimateCpuUsage(),
                memoryUsage: this.estimateMemoryUsage(),
                responseTime: this.statistics.averageResponseTime
            },
            recentActivity: this.getRecentActivity()
        };
        
        this.reports.realtime = report;
        
        if (this.config.monitoring.detailedLogging) {
            send({
                type: "info",
                target: "hook_effectiveness_monitor",
                action: "realtime_report",
                success_rate: (report.statistics.averageSuccessRate * 100).toFixed(1),
                response_time: report.statistics.averageResponseTime.toFixed(1),
                effectiveness: (report.statistics.overallEffectiveness * 100).toFixed(1)
            });
        }
    },
    
    generatePeriodicReport: function() {
        var report = {
            timestamp: Date.now(),
            type: "periodic",
            timeWindow: this.config.reporting.summaryInterval,
            statistics: Object.assign({}, this.statistics),
            trends: this.calculateTrends(),
            topPerformingHooks: this.getTopPerformingHooks(),
            bottomPerformingHooks: this.getBottomPerformingHooks(),
            performanceMetrics: this.getAggregatedPerformanceMetrics(),
            issues: this.identifyIssues()
        };
        
        this.reports.periodic.push(report);
        
        // Keep only recent periodic reports
        if (this.reports.periodic.length > 60) { // Keep last 60 reports
            this.reports.periodic.shift();
        }
        
        send({
            type: "info",
            target: "hook_effectiveness_monitor",
            action: "periodic_report_generated",
            hooks_count: this.monitor.activeHooks.size,
            effectiveness: (report.statistics.overallEffectiveness * 100).toFixed(1)
        });
    },
    
    generateSummaryReport: function() {
        var report = {
            timestamp: Date.now(),
            type: "summary",
            timeWindow: this.config.reporting.detailedInterval,
            overallStatistics: Object.assign({}, this.statistics),
            detailedMetrics: this.getDetailedMetrics(),
            hookAnalysis: this.generateHookAnalysis(),
            performanceAnalysis: this.generatePerformanceAnalysis(),
            stabilityAnalysis: this.generateStabilityAnalysis(),
            recommendations: this.generateRecommendations(),
            alerts: this.generateAlerts()
        };
        
        this.reports.summary = report;
        
        send({
            type: "info",
            target: "hook_effectiveness_monitor",
            action: "summary_report_generated"
        });
        this.logSummaryReport(report);
    },
    
    // === ANALYSIS METHODS ===
    getRecentActivity: function() {
        var currentTime = Date.now();
        var recentWindow = 30000; // 30 seconds
        var activity = {
            hookExecutions: 0,
            successfulExecutions: 0,
            failedExecutions: 0,
            bypassAttempts: 0,
            successfulBypasses: 0
        };
        
        // Count recent hook executions
        this.metrics.execution.forEach((execution) => {
            if (currentTime - execution.timestamp < recentWindow) {
                activity.hookExecutions++;
                if (execution.success) {
                    activity.successfulExecutions++;
                } else {
                    activity.failedExecutions++;
                }
            }
        });
        
        // Count recent bypass attempts
        this.metrics.success.forEach((success) => {
            if (currentTime - success.timestamp < recentWindow) {
                activity.bypassAttempts++;
                activity.successfulBypasses++;
            }
        });
        
        this.metrics.failure.forEach((failure) => {
            if (currentTime - failure.timestamp < recentWindow) {
                activity.bypassAttempts++;
            }
        });
        
        return activity;
    },
    
    calculateTrends: function() {
        if (!this.config.analysis.enableTrendAnalysis) return {};
        
        var trends = {
            successRate: this.calculateSuccessRateTrend(),
            responseTime: this.calculateResponseTimeTrend(),
            stability: this.calculateStabilityTrend(),
            performance: this.calculatePerformanceTrend()
        };
        
        return trends;
    },
    
    calculateSuccessRateTrend: function() {
        var recentReports = this.reports.periodic.slice(-10); // Last 10 reports
        if (recentReports.length < 2) return "stable";
        
        var rates = recentReports.map(r => r.statistics.averageSuccessRate);
        var trend = this.calculateTrendDirection(rates);
        
        return trend;
    },
    
    calculateResponseTimeTrend: function() {
        var recentReports = this.reports.periodic.slice(-10);
        if (recentReports.length < 2) return "stable";
        
        var times = recentReports.map(r => r.statistics.averageResponseTime);
        var trend = this.calculateTrendDirection(times);
        
        return trend;
    },
    
    calculateTrendDirection: function(values) {
        if (values.length < 2) return "stable";
        
        var sum = 0;
        for (var i = 1; i < values.length; i++) {
            sum += values[i] - values[i-1];
        }
        
        var average = sum / (values.length - 1);
        
        if (Math.abs(average) < 0.01) return "stable";
        return average > 0 ? "increasing" : "decreasing";
    },
    
    getTopPerformingHooks: function() {
        var hooks = [];
        
        this.monitor.activeHooks.forEach((hookData, hookId) => {
            if (hookData.executionCount > 0) {
                var successRate = hookData.successCount / hookData.executionCount;
                hooks.push({
                    hookId: hookId,
                    successRate: successRate,
                    executionTime: hookData.averageExecutionTime,
                    executionCount: hookData.executionCount
                });
            }
        });
        
        // Sort by success rate descending, then by execution time ascending
        hooks.sort((a, b) => {
            if (Math.abs(a.successRate - b.successRate) > 0.01) {
                return b.successRate - a.successRate;
            }
            return a.executionTime - b.executionTime;
        });
        
        return hooks.slice(0, 5); // Top 5
    },
    
    getBottomPerformingHooks: function() {
        var hooks = [];
        
        this.monitor.activeHooks.forEach((hookData, hookId) => {
            if (hookData.executionCount > 0) {
                var successRate = hookData.successCount / hookData.executionCount;
                hooks.push({
                    hookId: hookId,
                    successRate: successRate,
                    executionTime: hookData.averageExecutionTime,
                    executionCount: hookData.executionCount
                });
            }
        });
        
        // Sort by success rate ascending, then by execution time descending
        hooks.sort((a, b) => {
            if (Math.abs(a.successRate - b.successRate) > 0.01) {
                return a.successRate - b.successRate;
            }
            return b.executionTime - a.executionTime;
        });
        
        return hooks.slice(0, 3); // Bottom 3
    },
    
    identifyIssues: function() {
        var issues = [];
        
        // Check success rate issues
        if (this.statistics.averageSuccessRate < this.config.thresholds.minSuccessRate) {
            issues.push({
                type: "success_rate",
                severity: "high",
                description: "Success rate below threshold",
                value: this.statistics.averageSuccessRate,
                threshold: this.config.thresholds.minSuccessRate
            });
        }
        
        // Check response time issues
        if (this.statistics.averageResponseTime > this.config.thresholds.maxResponseTime) {
            issues.push({
                type: "response_time",
                severity: "medium",
                description: "Response time above threshold",
                value: this.statistics.averageResponseTime,
                threshold: this.config.thresholds.maxResponseTime
            });
        }
        
        // Check stability issues
        if (this.statistics.stabilityScore < this.config.thresholds.minStabilityScore) {
            issues.push({
                type: "stability",
                severity: "high",
                description: "Stability score below threshold",
                value: this.statistics.stabilityScore,
                threshold: this.config.thresholds.minStabilityScore
            });
        }
        
        // Check resource usage issues
        var cpuUsage = this.estimateCpuUsage();
        if (cpuUsage > this.config.thresholds.maxCpuUsage) {
            issues.push({
                type: "cpu_usage",
                severity: "medium",
                description: "CPU usage above threshold",
                value: cpuUsage,
                threshold: this.config.thresholds.maxCpuUsage
            });
        }
        
        var memoryUsage = this.estimateMemoryUsage();
        if (memoryUsage > this.config.thresholds.maxMemoryUsage) {
            issues.push({
                type: "memory_usage",
                severity: "medium",
                description: "Memory usage above threshold",
                value: memoryUsage,
                threshold: this.config.thresholds.maxMemoryUsage
            });
        }
        
        return issues;
    },
    
    // === UTILITY METHODS ===
    generateHookId: function(target) {
        try {
            var targetStr = target.toString();
            var hash = 0;
            for (var i = 0; i < targetStr.length; i++) {
                var char = targetStr.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32-bit integer
            }
            return "hook_" + Math.abs(hash).toString(16);
        } catch(e) {
            return "hook_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9);
        }
    },
    
    getCrashCount: function() {
        // Simplified crash detection
        return 0; // Would need to integrate with actual crash detection
    },
    
    getExceptionCount: function() {
        // Count exceptions from hook failures
        var exceptionCount = 0;
        this.metrics.execution.forEach((execution) => {
            if (!execution.success && execution.error) {
                exceptionCount++;
            }
        });
        return exceptionCount;
    },
    
    getHookFailureCount: function() {
        var failureCount = 0;
        this.metrics.installation.forEach((installation) => {
            if (!installation.success) {
                failureCount++;
            }
        });
        return failureCount;
    },
    
    calculateMemoryFootprint: function() {
        return this.estimateMemoryUsage();
    },
    
    calculateCpuTime: function() {
        // Estimate CPU time based on hook executions
        var totalExecutionTime = 0;
        this.monitor.activeHooks.forEach((hookData) => {
            totalExecutionTime += hookData.averageExecutionTime * hookData.executionCount;
        });
        return totalExecutionTime;
    },
    
    calculateHookOverhead: function() {
        // Calculate overhead introduced by hooks
        var baselineTime = 1.0; // Baseline execution time
        return this.statistics.averageResponseTime / baselineTime;
    },
    
    calculateNetworkUsage: function() {
        // Simplified network usage calculation
        return 0; // Would need actual network monitoring
    },
    
    calculateThroughput: function() {
        var timeWindow = 60000; // 1 minute
        var currentTime = Date.now();
        var executionCount = 0;
        
        this.metrics.execution.forEach((execution) => {
            if (currentTime - execution.timestamp < timeWindow) {
                executionCount++;
            }
        });
        
        return executionCount / (timeWindow / 1000); // executions per second
    },
    
    getActiveProcessCount: function() {
        // Simplified process count
        return 1; // Current process
    },
    
    // === DETAILED ANALYSIS ===
    getDetailedMetrics: function() {
        return {
            installation: {
                total: this.metrics.installation.size,
                successful: Array.from(this.metrics.installation.values()).filter(i => i.success).length,
                averageTime: this.calculateAverageInstallationTime()
            },
            execution: {
                total: this.metrics.execution.size,
                successful: Array.from(this.metrics.execution.values()).filter(e => e.success).length,
                averageTime: this.statistics.averageResponseTime
            },
            bypasses: {
                total: this.statistics.totalBypassAttempts,
                successful: this.statistics.successfulBypasses,
                successRate: this.statistics.totalBypassAttempts > 0 ? 
                    this.statistics.successfulBypasses / this.statistics.totalBypassAttempts : 0
            }
        };
    },
    
    calculateAverageInstallationTime: function() {
        var totalTime = 0;
        var count = 0;
        
        this.metrics.installation.forEach((installation) => {
            if (installation.success) {
                totalTime += installation.installTime;
                count++;
            }
        });
        
        return count > 0 ? totalTime / count : 0;
    },
    
    generateHookAnalysis: function() {
        var analysis = {
            totalHooks: this.monitor.activeHooks.size,
            averageSuccessRate: this.statistics.averageSuccessRate,
            mostActiveHooks: this.getMostActiveHooks(),
            leastActiveHooks: this.getLeastActiveHooks(),
            hooksByCategory: this.categorizeHooks()
        };
        
        return analysis;
    },
    
    getMostActiveHooks: function() {
        var hooks = [];
        
        this.monitor.activeHooks.forEach((hookData, hookId) => {
            hooks.push({
                hookId: hookId,
                executionCount: hookData.executionCount
            });
        });
        
        hooks.sort((a, b) => b.executionCount - a.executionCount);
        return hooks.slice(0, 5);
    },
    
    getLeastActiveHooks: function() {
        var hooks = [];
        
        this.monitor.activeHooks.forEach((hookData, hookId) => {
            hooks.push({
                hookId: hookId,
                executionCount: hookData.executionCount
            });
        });
        
        hooks.sort((a, b) => a.executionCount - b.executionCount);
        return hooks.slice(0, 3);
    },
    
    categorizeHooks: function() {
        // Simplified hook categorization
        return {
            "api_hooks": Math.floor(this.monitor.activeHooks.size * 0.6),
            "memory_hooks": Math.floor(this.monitor.activeHooks.size * 0.2),
            "network_hooks": Math.floor(this.monitor.activeHooks.size * 0.1),
            "other_hooks": Math.floor(this.monitor.activeHooks.size * 0.1)
        };
    },
    
    generatePerformanceAnalysis: function() {
        return {
            cpuUsage: this.estimateCpuUsage(),
            memoryUsage: this.estimateMemoryUsage(),
            responseTime: this.statistics.averageResponseTime,
            throughput: this.calculateThroughput(),
            performanceScore: this.statistics.performanceScore,
            bottlenecks: this.identifyBottlenecks()
        };
    },
    
    identifyBottlenecks: function() {
        var bottlenecks = [];
        
        if (this.statistics.averageResponseTime > this.config.thresholds.maxResponseTime) {
            bottlenecks.push("High response time");
        }
        
        if (this.estimateCpuUsage() > this.config.thresholds.maxCpuUsage) {
            bottlenecks.push("High CPU usage");
        }
        
        if (this.estimateMemoryUsage() > this.config.thresholds.maxMemoryUsage) {
            bottlenecks.push("High memory usage");
        }
        
        return bottlenecks;
    },
    
    generateStabilityAnalysis: function() {
        return {
            stabilityScore: this.statistics.stabilityScore,
            uptime: Date.now() - this.monitor.startTime,
            crashCount: this.getCrashCount(),
            exceptionCount: this.getExceptionCount(),
            hookFailures: this.getHookFailureCount(),
            stabilityTrend: this.calculateStabilityTrend()
        };
    },
    
    calculateStabilityTrend: function() {
        var recentReports = this.reports.periodic.slice(-5);
        if (recentReports.length < 2) return "stable";
        
        var scores = recentReports.map(r => r.statistics.stabilityScore);
        return this.calculateTrendDirection(scores);
    },
    
    generateRecommendations: function() {
        var recommendations = [];
        
        if (this.statistics.averageSuccessRate < 0.9) {
            recommendations.push("Consider optimizing hook placement for better success rates");
        }
        
        if (this.statistics.averageResponseTime > 50) {
            recommendations.push("Hook execution time is high, consider optimizing hook logic");
        }
        
        if (this.estimateCpuUsage() > 8) {
            recommendations.push("CPU usage is high, consider reducing hook frequency");
        }
        
        if (this.statistics.stabilityScore < 0.95) {
            recommendations.push("Stability issues detected, review hook error handling");
        }
        
        return recommendations;
    },
    
    generateAlerts: function() {
        var alerts = [];
        var issues = this.identifyIssues();
        
        issues.forEach((issue) => {
            if (issue.severity === "high") {
                alerts.push({
                    level: "critical",
                    message: "CRITICAL: " + issue.description,
                    value: issue.value,
                    threshold: issue.threshold
                });
            } else if (issue.severity === "medium") {
                alerts.push({
                    level: "warning",
                    message: "WARNING: " + issue.description,
                    value: issue.value,
                    threshold: issue.threshold
                });
            }
        });
        
        return alerts;
    },
    
    getAggregatedPerformanceMetrics: function() {
        var recentMetrics = [];
        var currentTime = Date.now();
        var timeWindow = this.config.reporting.summaryInterval;
        
        this.metrics.performance.forEach((metric) => {
            if (currentTime - metric.timestamp < timeWindow) {
                recentMetrics.push(metric);
            }
        });
        
        if (recentMetrics.length === 0) {
            return {
                averageCpuUsage: 0,
                averageMemoryUsage: 0,
                averageResponseTime: 0,
                averageThroughput: 0
            };
        }
        
        var totalCpu = recentMetrics.reduce((sum, m) => sum + m.cpuUsage, 0);
        var totalMemory = recentMetrics.reduce((sum, m) => sum + m.memoryUsage, 0);
        var totalResponse = recentMetrics.reduce((sum, m) => sum + m.averageResponseTime, 0);
        var totalThroughput = recentMetrics.reduce((sum, m) => sum + m.throughput, 0);
        
        return {
            averageCpuUsage: totalCpu / recentMetrics.length,
            averageMemoryUsage: totalMemory / recentMetrics.length,
            averageResponseTime: totalResponse / recentMetrics.length,
            averageThroughput: totalThroughput / recentMetrics.length
        };
    },
    
    // === ANALYSIS ENGINE ===
    setupAnalysisEngine: function() {
        if (!this.config.analysis.enableTrendAnalysis) return;
        
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "setting_up_analysis_engine"
        });
        
        // Start trend analysis
        setInterval(() => {
            this.performTrendAnalysis();
        }, 60000); // Every minute
        
        // Start correlation analysis
        if (this.config.analysis.enableCorrelationAnalysis) {
            setInterval(() => {
                this.performCorrelationAnalysis();
            }, 300000); // Every 5 minutes
        }
        
        // Start anomaly detection
        if (this.config.analysis.enableAnomalyDetection) {
            setInterval(() => {
                this.performAnomalyDetection();
            }, 120000); // Every 2 minutes
        }
        
        send({
            type: "status",
            target: "hook_effectiveness_monitor",
            action: "analysis_engine_started"
        });
    },
    
    performTrendAnalysis: function() {
        this.reports.trends = this.calculateTrends();
    },
    
    performCorrelationAnalysis: function() {
        var correlations = {};
        
        // Analyze correlation between success rate and response time
        correlations.successRate_responseTime = this.calculateCorrelation(
            this.getSuccessRateHistory(),
            this.getResponseTimeHistory()
        );
        
        // Analyze correlation between hook count and performance
        correlations.hookCount_performance = this.calculateCorrelation(
            this.getHookCountHistory(),
            this.getPerformanceHistory()
        );
        
        this.reports.correlations = correlations;
    },
    
    calculateCorrelation: function(series1, series2) {
        if (series1.length !== series2.length || series1.length < 2) {
            return 0;
        }
        
        var mean1 = series1.reduce((sum, val) => sum + val, 0) / series1.length;
        var mean2 = series2.reduce((sum, val) => sum + val, 0) / series2.length;
        
        var numerator = 0;
        var sum1Sq = 0;
        var sum2Sq = 0;
        
        for (var i = 0; i < series1.length; i++) {
            var diff1 = series1[i] - mean1;
            var diff2 = series2[i] - mean2;
            
            numerator += diff1 * diff2;
            sum1Sq += diff1 * diff1;
            sum2Sq += diff2 * diff2;
        }
        
        var denominator = Math.sqrt(sum1Sq * sum2Sq);
        return denominator === 0 ? 0 : numerator / denominator;
    },
    
    getSuccessRateHistory: function() {
        return this.reports.periodic.map(r => r.statistics.averageSuccessRate);
    },
    
    getResponseTimeHistory: function() {
        return this.reports.periodic.map(r => r.statistics.averageResponseTime);
    },
    
    getHookCountHistory: function() {
        return this.reports.periodic.map(r => r.statistics.totalHooksMonitored);
    },
    
    getPerformanceHistory: function() {
        return this.reports.periodic.map(r => r.statistics.performanceScore);
    },
    
    performAnomalyDetection: function() {
        var anomalies = [];
        
        // Detect success rate anomalies
        var successRateAnomaly = this.detectAnomalyInSeries(
            this.getSuccessRateHistory(),
            "success_rate"
        );
        if (successRateAnomaly) {
            anomalies.push(successRateAnomaly);
        }
        
        // Detect response time anomalies
        var responseTimeAnomaly = this.detectAnomalyInSeries(
            this.getResponseTimeHistory(),
            "response_time"
        );
        if (responseTimeAnomaly) {
            anomalies.push(responseTimeAnomaly);
        }
        
        this.reports.anomalies = anomalies;
        
        if (anomalies.length > 0) {
            send({
                type: "detection",
                target: "hook_effectiveness_monitor",
                action: "anomalies_detected",
                anomaly_count: anomalies.length
            });
        }
    },
    
    detectAnomalyInSeries: function(series, seriesName) {
        if (series.length < 5) return null;
        
        // Calculate rolling average and standard deviation
        var recent = series.slice(-5);
        var mean = recent.reduce((sum, val) => sum + val, 0) / recent.length;
        var variance = recent.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / recent.length;
        var stdDev = Math.sqrt(variance);
        
        var currentValue = series[series.length - 1];
        var deviation = Math.abs(currentValue - mean) / stdDev;
        
        if (deviation > 2.0) { // 2 standard deviations
            return {
                type: seriesName,
                timestamp: Date.now(),
                value: currentValue,
                mean: mean,
                stdDev: stdDev,
                deviation: deviation,
                severity: deviation > 3.0 ? "high" : "medium"
            };
        }
        
        return null;
    },
    
    // === REPORT LOGGING ===
    logSummaryReport: function(report) {
        send({
            type: "info",
            target: "hook_effectiveness_monitor",
            action: "summary_report_details",
            total_hooks: report.overallStatistics.totalHooksMonitored,
            success_rate: (report.overallStatistics.averageSuccessRate * 100).toFixed(1),
            response_time: report.overallStatistics.averageResponseTime.toFixed(1),
            stability_score: (report.overallStatistics.stabilityScore * 100).toFixed(1),
            performance_score: (report.overallStatistics.performanceScore * 100).toFixed(1),
            overall_effectiveness: (report.overallStatistics.overallEffectiveness * 100).toFixed(1),
            cpu_usage: report.performanceAnalysis.cpuUsage.toFixed(1),
            memory_usage: report.performanceAnalysis.memoryUsage.toFixed(1),
            throughput: report.performanceAnalysis.throughput.toFixed(1)
        });

        if (report.alerts.length > 0) {
            for (var i = 0; i < report.alerts.length; i++) {
                var alert = report.alerts[i];
                send({
                    type: alert.level === "critical" ? "error" : "warning",
                    target: "hook_effectiveness_monitor",
                    action: "summary_alert",
                    alert_level: alert.level,
                    alert_message: alert.message
                });
            }
        }
        
        if (report.recommendations.length > 0) {
            for (var i = 0; i < report.recommendations.length; i++) {
                send({
                    type: "info",
                    target: "hook_effectiveness_monitor",
                    action: "recommendation",
                    recommendation: report.recommendations[i]
                });
            }
        }
    },
    
    // === CLEANUP ===
    cleanupOldData: function() {
        var currentTime = Date.now();
        var retentionTime = this.config.reporting.retentionPeriod;
        
        // Clean up old metrics
        this.cleanupMetricsOlderThan(currentTime - retentionTime);
        
        // Clean up old reports
        this.cleanupReportsOlderThan(currentTime - retentionTime);
    },
    
    cleanupMetricsOlderThan: function(cutoffTime) {
        var metricsToClean = [
            this.metrics.installation,
            this.metrics.execution,
            this.metrics.success,
            this.metrics.failure,
            this.metrics.performance,
            this.metrics.stability,
            this.metrics.resource
        ];
        
        metricsToClean.forEach((metricsMap) => {
            metricsMap.forEach((metric, key) => {
                if (metric.timestamp && metric.timestamp < cutoffTime) {
                    metricsMap.delete(key);
                }
            });
        });
    },
    
    cleanupReportsOlderThan: function(cutoffTime) {
        this.reports.periodic = this.reports.periodic.filter(
            report => report.timestamp >= cutoffTime
        );
    },
    
    // === API METHODS ===
    getHookEffectivenessReport: function() {
        return {
            statistics: this.statistics,
            activeHooks: this.monitor.activeHooks.size,
            realtimeReport: this.reports.realtime,
            summaryReport: this.reports.summary,
            trends: this.reports.trends,
            correlations: this.reports.correlations,
            anomalies: this.reports.anomalies
        };
    },
    
    getHookDetails: function(hookId) {
        return this.monitor.activeHooks.get(hookId);
    },
    
    getPerformanceMetrics: function() {
        return {
            cpuUsage: this.estimateCpuUsage(),
            memoryUsage: this.estimateMemoryUsage(),
            responseTime: this.statistics.averageResponseTime,
            throughput: this.calculateThroughput(),
            performanceScore: this.statistics.performanceScore
        };
    },
    
    // === INSTALLATION SUMMARY ===
    installSummary: function() {
        setTimeout(() => {
            send({
                type: "status",
                target: "hook_effectiveness_monitor",
                action: "installation_summary",
                monitoring_active: this.monitor.isRunning,
                active_hooks: this.monitor.activeHooks.size,
                total_measurements: this.statistics.totalMeasurements,
                overall_effectiveness: (this.statistics.overallEffectiveness * 100).toFixed(1)
            });
            
            var activeFeatures = [];
            
            if (this.config.monitoring.enabled) {
                activeFeatures.push("Real-Time Hook Monitoring");
            }
            if (this.config.monitoring.performanceMetrics) {
                activeFeatures.push("Performance Metrics Collection");
            }
            if (this.config.monitoring.successRateTracking) {
                activeFeatures.push("Success Rate Tracking");
            }
            if (this.config.reporting.enableRealtimeReports) {
                activeFeatures.push("Real-Time Reporting");
            }
            if (this.config.reporting.enableSummaryReports) {
                activeFeatures.push("Summary Reporting");
            }
            if (this.config.analysis.enableTrendAnalysis) {
                activeFeatures.push("Trend Analysis");
            }
            if (this.config.analysis.enableCorrelationAnalysis) {
                activeFeatures.push("Correlation Analysis");
            }
            if (this.config.analysis.enableAnomalyDetection) {
                activeFeatures.push("Anomaly Detection");
            }
            
            send({
                type: "info",
                target: "hook_effectiveness_monitor",
                action: "active_features",
                features: activeFeatures
            });
            
            send({
                type: "success",
                target: "hook_effectiveness_monitor",
                action: "system_active",
                message: "Hook effectiveness monitoring system is now ACTIVE!"
            });
        }, 100);
    }
}