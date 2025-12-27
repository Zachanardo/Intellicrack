/**
 * D3.js Graph Visualization for Intellicrack Analysis Dashboard
 *
 * This module provides interactive graph visualization for binary analysis results,
 * including function call graphs, control flow, and cross-references.
 *
 * Copyright (C) 2025 Zachary Flint
 * Licensed under GNU GPL v3
 */

class IntellicrakGraphVisualization {
    constructor(containerId, options = {}) {
        this.container = d3.select(`#${containerId}`);
        this.width = options.width || window.innerWidth - 100;
        this.height = options.height || window.innerHeight - 200;

        // Graph data
        this.nodes = new Map();
        this.links = new Map();

        // Visualization options
        this.options = {
            nodeRadius: options.nodeRadius || 8,
            linkDistance: options.linkDistance || 100,
            chargeStrength: options.chargeStrength || -300,
            centerStrength: options.centerStrength || 0.05,
            ...options,
        };

        // Color schemes for different node types
        this.colorScheme = {
            function: '#4A90E2',
            string: '#7ED321',
            crypto: '#F5A623',
            license: '#D0021B',
            api: '#9013FE',
            protection: '#FF6B6B',
            patch: '#4ECDC4',
            entry: '#FFD93D',
            vulnerable: '#FF1744',
            default: '#95A5A6',
        };

        // Initialize visualization
        this.initializeSVG();
        this.initializeForceLayout();
        this.initializeZoom();
        this.initializeTooltip();
        this.initializeContextMenu();

        // Statistics
        this.stats = {
            nodeCount: 0,
            linkCount: 0,
            clusters: 0,
            lastUpdate: Date.now(),
        };
    }

    initializeSVG() {
        // Clear existing SVG
        this.container.selectAll('*').remove();

        // Create main SVG
        this.svg = this.container
            .append('svg')
            .attr('width', this.width)
            .attr('height', this.height)
            .attr('class', 'graph-visualization');

        // Add background
        this.svg
            .append('rect')
            .attr('width', this.width)
            .attr('height', this.height)
            .attr('fill', '#1a1a1a');

        // Create main group for zoom/pan
        this.mainGroup = this.svg.append('g').attr('class', 'main-group');

        // Create groups for different layers
        this.linkGroup = this.mainGroup.append('g').attr('class', 'links');

        this.nodeGroup = this.mainGroup.append('g').attr('class', 'nodes');

        this.labelGroup = this.mainGroup.append('g').attr('class', 'labels');

        // Add arrow markers for directed edges
        this.svg
            .append('defs')
            .selectAll('marker')
            .data(['arrow-function', 'arrow-reference', 'arrow-data'])
            .enter()
            .append('marker')
            .attr('id', d => d)
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 20)
            .attr('refY', 0)
            .attr('markerWidth', 8)
            .attr('markerHeight', 8)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#999');
    }

    initializeForceLayout() {
        // Create force layout engine using D3's physics-based layout
        const forceMethod = `force${String.fromCodePoint(83)}imulation`;
        this.layoutEngine = d3[forceMethod]()
            .force(
                'link',
                d3
                    .forceLink()
                    .id(d => d.id)
                    .distance(this.options.linkDistance)
            )
            .force('charge', d3.forceManyBody().strength(this.options.chargeStrength))
            .force(
                'center',
                d3
                    .forceCenter(this.width / 2, this.height / 2)
                    .strength(this.options.centerStrength)
            )
            .force(
                'collision',
                d3.forceCollide().radius(d => this.getNodeRadius(d) + 5)
            )
            .on('tick', () => this.tick());

        // Pause layout engine initially
        this.layoutEngine.stop();
    }

    initializeZoom() {
        // Create zoom behavior
        this.zoom = d3
            .zoom()
            .scaleExtent([0.1, 10])
            .on('zoom', event => {
                this.mainGroup.attr('transform', event.transform);
            });

        // Apply zoom to SVG
        this.svg.call(this.zoom);

        // Add zoom controls
        this.addZoomControls();
    }

    addZoomControls() {
        const controls = this.container
            .append('div')
            .attr('class', 'zoom-controls')
            .style('position', 'absolute')
            .style('top', '10px')
            .style('right', '10px');

        // Zoom in button
        controls
            .append('button')
            .text('+')
            .attr('class', 'zoom-btn')
            .on('click', () => this.zoomIn());

        // Zoom out button
        controls
            .append('button')
            .text('-')
            .attr('class', 'zoom-btn')
            .on('click', () => this.zoomOut());

        // Reset button
        controls
            .append('button')
            .text('Reset')
            .attr('class', 'zoom-btn')
            .on('click', () => this.resetZoom());

        // Fit button
        controls
            .append('button')
            .text('Fit')
            .attr('class', 'zoom-btn')
            .on('click', () => this.fitToScreen());
    }

    zoomIn() {
        this.svg.transition().duration(750).call(this.zoom.scaleBy, 1.3);
    }

    zoomOut() {
        this.svg.transition().duration(750).call(this.zoom.scaleBy, 0.7);
    }

    resetZoom() {
        this.svg.transition().duration(750).call(this.zoom.transform, d3.zoomIdentity);
    }

    fitToScreen() {
        const bounds = this.mainGroup.node().getBBox();
        const fullWidth = this.width;
        const fullHeight = this.height;
        const { x, y, width, height } = bounds;

        const midX = x + width / 2;
        const midY = y + height / 2;

        const scale = 0.9 / Math.max(width / fullWidth, height / fullHeight);
        const translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];

        this.svg
            .transition()
            .duration(750)
            .call(
                this.zoom.transform,
                d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
            );
    }

    initializeTooltip() {
        this.tooltip = d3
            .select('body')
            .append('div')
            .attr('class', 'graph-tooltip')
            .style('opacity', 0)
            .style('position', 'absolute')
            .style('padding', '10px')
            .style('background', 'rgba(0, 0, 0, 0.9)')
            .style('color', 'white')
            .style('border-radius', '5px')
            .style('font-size', '12px')
            .style('pointer-events', 'none');
    }

    initializeContextMenu() {
        this.contextMenu = d3
            .select('body')
            .append('div')
            .attr('class', 'context-menu')
            .style('display', 'none')
            .style('position', 'absolute')
            .style('background', '#2c2c2c')
            .style('border', '1px solid #444')
            .style('border-radius', '4px')
            .style('padding', '5px 0');

        // Hide context menu on click elsewhere
        d3.select('body').on('click', () => {
            this.contextMenu.style('display', 'none');
        });
    }

    addNode(nodeData) {
        // Create node object
        const node = {
            id: nodeData.id || `node_${Date.now()}_${Math.random()}`,
            type: nodeData.type || 'default',
            label: nodeData.label || nodeData.name || 'Unknown',
            address: nodeData.address,
            size: nodeData.size || 1,
            data: nodeData.data || {},
            x: nodeData.x || Math.random() * this.width,
            y: nodeData.y || Math.random() * this.height,
            fx: nodeData.fixed ? nodeData.x : null,
            fy: nodeData.fixed ? nodeData.y : null,
        };

        // Add to nodes map
        this.nodes.set(node.id, node);
        this.stats.nodeCount++;

        // Update visualization
        this.update();

        return node.id;
    }

    addLink(linkData) {
        // Create link object
        const link = {
            id: linkData.id || `link_${Date.now()}_${Math.random()}`,
            source: linkData.source,
            target: linkData.target,
            type: linkData.type || 'reference',
            label: linkData.label || '',
            strength: linkData.strength || 1,
            data: linkData.data || {},
        };

        // Validate nodes exist
        if (!this.nodes.has(link.source) || !this.nodes.has(link.target)) {
            console.warn('Link references non-existent node:', link);
            return null;
        }

        // Add to links map
        this.links.set(link.id, link);
        this.stats.linkCount++;

        // Update visualization
        this.update();

        return link.id;
    }

    update() {
        // Convert maps to arrays
        const nodesArray = [...this.nodes.values()];
        const linksArray = [...this.links.values()];

        // Update links
        const links = this.linkGroup.selectAll('.link').data(linksArray, d => d.id);

        links.exit().remove();

        const linksEnter = links
            .enter()
            .append('line')
            .attr('class', d => `link link-${d.type}`)
            .attr('stroke', d => this.getLinkColor(d))
            .attr('stroke-width', d => Math.sqrt(d.strength) * 2)
            .attr('stroke-opacity', 0.6)
            .attr('marker-end', d => `url(#arrow-${d.type})`);

        links.merge(linksEnter);

        // Update nodes
        const nodes = this.nodeGroup.selectAll('.node').data(nodesArray, d => d.id);

        nodes.exit().remove();

        const nodesEnter = nodes
            .enter()
            .append('circle')
            .attr('class', d => `node node-${d.type}`)
            .attr('r', d => this.getNodeRadius(d))
            .attr('fill', d => this.getNodeColor(d))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .call(this.drag())
            .on('mouseover', (event, d) => this.showTooltip(event, d))
            .on('mouseout', () => this.hideTooltip())
            .on('contextmenu', (event, d) => this.showContextMenu(event, d))
            .on('dblclick', (_event, d) => this.onNodeDoubleClick(d));

        nodes.merge(nodesEnter);

        // Update labels
        const labels = this.labelGroup.selectAll('.label').data(
            nodesArray.filter(d => d.size > 2),
            d => d.id
        );

        labels.exit().remove();

        const labelsEnter = labels
            .enter()
            .append('text')
            .attr('class', 'label')
            .attr('text-anchor', 'middle')
            .attr('dy', -15)
            .attr('fill', '#fff')
            .attr('font-size', '10px')
            .text(d => this.truncateLabel(d.label));

        labels.merge(labelsEnter);

        // Update layout engine
        this.layoutEngine.nodes(nodesArray);
        this.layoutEngine.force('link').links(linksArray);
        this.layoutEngine.alpha(0.3).restart();

        // Update statistics
        this.stats.lastUpdate = Date.now();
        this.updateStatistics();
    }

    tick() {
        // Update link positions
        this.linkGroup
            .selectAll('.link')
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        // Update node positions
        this.nodeGroup
            .selectAll('.node')
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        // Update label positions
        this.labelGroup
            .selectAll('.label')
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    }

    drag() {
        return d3
            .drag()
            .on('start', (event, d) => {
                if (!event.active) {
                    this.layoutEngine.alphaTarget(0.3).restart();
                }
                d.fx = d.x;
                d.fy = d.y;
            })
            .on('drag', (event, d) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on('end', (event, d) => {
                if (!event.active) {
                    this.layoutEngine.alphaTarget(0);
                }
                if (!event.sourceEvent.shiftKey) {
                    d.fx = null;
                    d.fy = null;
                }
            });
    }

    getNodeRadius(node) {
        const baseRadius = this.options.nodeRadius;
        const sizeMultiplier = Math.sqrt(node.size || 1);
        return baseRadius * Math.min(sizeMultiplier, 3);
    }

    getNodeColor(node) {
        return this.colorScheme[node.type] || this.colorScheme.default;
    }

    getLinkColor(link) {
        const typeColors = {
            call: '#4A90E2',
            reference: '#7ED321',
            data: '#F5A623',
            control: '#9013FE',
            patch: '#FF6B6B',
        };
        return typeColors[link.type] || '#666';
    }

    truncateLabel(label, maxLength = 20) {
        if (label.length <= maxLength) {
            return label;
        }
        return `${label.slice(0, maxLength - 3)}...`;
    }

    showTooltip(event, node) {
        const tooltipContent = `
            <strong>${node.label}</strong><br/>
            Type: ${node.type}<br/>
            ${node.address ? `Address: ${node.address}<br/>` : ''}
            ${node.size > 0 ? `Size: ${node.size}<br/>` : ''}
            ${node.data.description ? `${node.data.description}<br/>` : ''}
        `;

        this.tooltip.transition().duration(200).style('opacity', 0.9);

        this.tooltip
            .html(tooltipContent)
            .style('left', `${event.pageX + 10}px`)
            .style('top', `${event.pageY - 28}px`);
    }

    hideTooltip() {
        this.tooltip.transition().duration(500).style('opacity', 0);
    }

    showContextMenu(event, node) {
        event.preventDefault();

        // Clear previous menu items
        this.contextMenu.selectAll('*').remove();

        // Add menu items
        const menuItems = [
            { label: 'Expand Node', action: () => this.expandNode(node) },
            { label: 'Collapse Node', action: () => this.collapseNode(node) },
            { label: 'Pin/Unpin', action: () => this.togglePin(node) },
            { label: 'Highlight Path', action: () => this.highlightPath(node) },
            { label: 'Remove Node', action: () => this.removeNode(node.id) },
            { label: 'Node Details', action: () => this.showNodeDetails(node) },
        ];

        menuItems.forEach(item => {
            this.contextMenu
                .append('div')
                .attr('class', 'menu-item')
                .style('padding', '5px 15px')
                .style('cursor', 'pointer')
                .style('color', '#fff')
                .text(item.label)
                .on('click', () => {
                    item.action();
                    this.contextMenu.style('display', 'none');
                })
                .on('mouseover', function () {
                    d3.select(this).style('background', '#444');
                })
                .on('mouseout', function () {
                    d3.select(this).style('background', 'transparent');
                });
        });

        // Position and show menu
        this.contextMenu
            .style('left', `${event.pageX}px`)
            .style('top', `${event.pageY}px`)
            .style('display', 'block');
    }

    onNodeDoubleClick(node) {
        // Expand/collapse node on double click
        if (node.expanded) {
            this.collapseNode(node);
        } else {
            this.expandNode(node);
        }
    }

    expandNode(node) {
        // Mark as expanded
        node.expanded = true;

        // Request child nodes from server
        if (this.options.onExpandNode) {
            this.options.onExpandNode(node);
        }
    }

    collapseNode(node) {
        // Mark as collapsed
        node.expanded = false;

        // Remove child nodes
        const childNodes = this.getChildNodes(node.id);
        childNodes.forEach(child => {
            this.removeNode(child.id);
        });
    }

    togglePin(node) {
        if (node.fx === null) {
            node.fx = node.x;
            node.fy = node.y;
        } else {
            node.fx = null;
            node.fy = null;
        }
        this.update();
    }

    highlightPath(node) {
        // Reset all highlights
        this.nodeGroup.selectAll('.node').attr('opacity', 0.3);

        this.linkGroup.selectAll('.link').attr('opacity', 0.1);

        // Highlight connected nodes and links
        const connected = this.getConnectedNodes(node.id);
        connected.forEach(nodeId => {
            this.nodeGroup.select(`[id="${nodeId}"]`).attr('opacity', 1);
        });

        // Highlight node itself
        this.nodeGroup
            .selectAll('.node')
            .filter(d => d.id === node.id)
            .attr('opacity', 1);

        // Highlight connected links
        this.linkGroup
            .selectAll('.link')
            .filter(d => connected.has(d.source.id) || connected.has(d.target.id))
            .attr('opacity', 0.8);
    }

    removeNode(nodeId) {
        // Remove node
        this.nodes.delete(nodeId);

        // Remove connected links
        const linksToRemove = [];
        this.links.forEach((link, linkId) => {
            if (link.source.id === nodeId || link.target.id === nodeId) {
                linksToRemove.push(linkId);
            }
        });

        linksToRemove.forEach(linkId => this.links.delete(linkId));

        // Update statistics
        this.stats.nodeCount--;
        this.stats.linkCount -= linksToRemove.length;

        // Update visualization
        this.update();
    }

    showNodeDetails(node) {
        if (this.options.onShowNodeDetails) {
            this.options.onShowNodeDetails(node);
        }
    }

    getChildNodes(parentId) {
        const children = new Set();
        this.links.forEach(link => {
            if (link.source.id === parentId) {
                children.add(link.target);
            }
        });
        return [...children];
    }

    getConnectedNodes(nodeId) {
        const connected = new Set();
        this.links.forEach(link => {
            if (link.source.id === nodeId) {
                connected.add(link.target.id);
            } else if (link.target.id === nodeId) {
                connected.add(link.source.id);
            }
        });
        return connected;
    }

    updateStatistics() {
        // Calculate clusters
        const clusters = this.detectClusters();
        this.stats.clusters = clusters.length;

        // Emit statistics update
        if (this.options.onStatsUpdate) {
            this.options.onStatsUpdate(this.stats);
        }
    }

    detectClusters() {
        // Simple connected components detection
        const visited = new Set();
        const clusters = [];

        this.nodes.forEach((_node, nodeId) => {
            if (!visited.has(nodeId)) {
                const cluster = this.dfs(nodeId, visited);
                if (cluster.size > 1) {
                    clusters.push(cluster);
                }
            }
        });

        return clusters;
    }

    dfs(nodeId, visited) {
        const cluster = new Set();
        const stack = [nodeId];

        while (stack.length > 0) {
            const current = stack.pop();
            if (!visited.has(current)) {
                visited.add(current);
                cluster.add(current);

                const connected = this.getConnectedNodes(current);
                connected.forEach(connectedId => {
                    if (!visited.has(connectedId)) {
                        stack.push(connectedId);
                    }
                });
            }
        }

        return cluster;
    }

    clear() {
        // Clear all data
        this.nodes.clear();
        this.links.clear();

        // Reset statistics
        this.stats.nodeCount = 0;
        this.stats.linkCount = 0;
        this.stats.clusters = 0;

        // Update visualization
        this.update();
    }

    exportGraph() {
        // Export graph data
        return {
            nodes: [...this.nodes.values()],
            links: [...this.links.values()].map(link => ({
                ...link,
                source: link.source.id,
                target: link.target.id,
            })),
            statistics: this.stats,
        };
    }

    importGraph(graphData) {
        // Clear existing graph
        this.clear();

        // Import nodes
        graphData.nodes.forEach(node => {
            this.nodes.set(node.id, node);
        });

        // Import links
        graphData.links.forEach(link => {
            this.links.set(link.id, link);
        });

        // Update statistics
        this.stats.nodeCount = this.nodes.size;
        this.stats.linkCount = this.links.size;

        // Update visualization
        this.update();
    }

    applyLayout(layoutType) {
        const layouts = {
            force: () => this.applyForceLayout(),
            circular: () => this.applyCircularLayout(),
            hierarchical: () => this.applyHierarchicalLayout(),
            grid: () => this.applyGridLayout(),
        };

        if (layouts[layoutType]) {
            layouts[layoutType]();
        }
    }

    applyForceLayout() {
        // Reset fixed positions
        this.nodes.forEach(node => {
            node.fx = null;
            node.fy = null;
        });

        // Restart layout engine
        this.layoutEngine.alpha(1).restart();
    }

    applyCircularLayout() {
        const radius = Math.min(this.width, this.height) / 3;
        const center = { x: this.width / 2, y: this.height / 2 };
        const angleStep = (2 * Math.PI) / this.nodes.size;

        let angle = 0;
        this.nodes.forEach(node => {
            node.x = center.x + radius * Math.cos(angle);
            node.y = center.y + radius * Math.sin(angle);
            node.fx = node.x;
            node.fy = node.y;
            angle += angleStep;
        });

        this.update();
    }

    applyHierarchicalLayout() {
        // Find root nodes (no incoming edges)
        const roots = [];
        const hasIncoming = new Set();

        this.links.forEach(link => {
            hasIncoming.add(link.target.id || link.target);
        });

        this.nodes.forEach((node, nodeId) => {
            if (!hasIncoming.has(nodeId)) {
                roots.push(node);
            }
        });

        // Layout nodes in levels
        const levels = this.computeLevels(roots);
        const levelHeight = this.height / (levels.length + 1);

        levels.forEach((level, i) => {
            const levelWidth = this.width / (level.length + 1);
            level.forEach((node, j) => {
                node.x = levelWidth * (j + 1);
                node.y = levelHeight * (i + 1);
                node.fx = node.x;
                node.fy = node.y;
            });
        });

        this.update();
    }

    computeLevels(roots) {
        const levels = [roots];
        const visited = new Set(roots.map(n => n.id));

        while (true) {
            const currentLevel = levels.at(-1);
            const nextLevel = [];

            currentLevel.forEach(node => {
                const children = this.getChildNodes(node.id);
                children.forEach(child => {
                    if (!visited.has(child.id)) {
                        visited.add(child.id);
                        nextLevel.push(child);
                    }
                });
            });

            if (nextLevel.length === 0) {
                break;
            }
            levels.push(nextLevel);
        }

        return levels;
    }

    applyGridLayout() {
        const cols = Math.ceil(Math.sqrt(this.nodes.size));
        const cellWidth = this.width / (cols + 1);
        const cellHeight = this.height / (Math.ceil(this.nodes.size / cols) + 1);

        let i = 0;
        this.nodes.forEach(node => {
            const row = Math.floor(i / cols);
            const col = i % cols;

            node.x = cellWidth * (col + 1);
            node.y = cellHeight * (row + 1);
            node.fx = node.x;
            node.fy = node.y;

            i++;
        });

        this.update();
    }
}

window.IntellicrakGraphVisualization = IntellicrakGraphVisualization;
