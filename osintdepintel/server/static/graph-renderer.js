/**
 * DependencyGraphRenderer - Lightweight Force-Directed Graph Layout on HTML5 Canvas
 * Handles Pan, Zoom, Node Dragging, Custom Styling, and High-DPI rendering.
 */
class DependencyGraphRenderer {
    constructor(canvasId, onNodeSelected) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.onNodeSelected = onNodeSelected;

        // Graph Data
        this.nodes = [];
        this.edges = [];
        this.nodesMap = new Map();

        // Viewport State (Pan & Zoom)
        this.zoom = 1.0;
        this.panX = 0;
        this.panY = 0;

        // Interaction State
        this.draggedNode = null;
        this.selectedNode = null;
        this.isPanning = false;
        this.lastMouseX = 0;
        this.lastMouseY = 0;
        
        // Physics constants
        this.repulsionConstant = 3500;
        this.springConstant = 0.08;
        this.springLength = 120;
        this.gravityConstant = 0.02;
        this.damping = 0.85;
        this.physicsIterations = 200; // Layout settling limit
        this.settled = false;

        // Setup event listeners
        this.setupEvents();
        this.resize();
    }

    setData(nodesData, edgesData) {
        this.nodes = [];
        this.edges = [];
        this.nodesMap.clear();
        this.selectedNode = null;
        this.settled = false;

        const width = this.canvas.width / window.devicePixelRatio;
        const height = this.canvas.height / window.devicePixelRatio;

        // Parse nodes
        Object.entries(nodesData).forEach(([key, record], index) => {
            // Position nodes in a spiral to prevent overlap at origin
            const angle = index * 0.5;
            const radius = 30 + index * 10;
            const node = {
                key: key,
                name: record.name,
                ecosystem: record.ecosystem.toLowerCase(),
                version: record.version || 'unknown',
                status: record.status,
                confidence: record.confidence,
                x: width / 2 + Math.cos(angle) * radius,
                y: height / 2 + Math.sin(angle) * radius,
                vx: 0,
                vy: 0,
                radius: 40,
                data: record
            };
            this.nodes.push(node);
            this.nodesMap.set(key, node);
        });

        // Parse edges
        edgesData.forEach(edge => {
            const sourceNode = this.nodesMap.get(edge.parent_key);
            const targetNode = this.nodesMap.get(edge.child_key);
            if (sourceNode && targetNode) {
                this.edges.push({
                    source: sourceNode,
                    target: targetNode,
                    status: edge.status,
                    confidence: edge.confidence
                });
            }
        });

        this.fitToScreen();
        this.startLoop();
    }

    resize() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.canvas.style.width = rect.width + 'px';
        this.canvas.style.height = rect.height + 'px';
        this.ctx.scale(dpr, dpr);
        
        if (this.nodes.length > 0) {
            this.settled = false;
            this.startLoop();
        }
    }

    fitToScreen() {
        if (this.nodes.length === 0) return;

        // Find bounding box
        let minX = Infinity, maxX = -Infinity;
        let minY = Infinity, maxY = -Infinity;

        this.nodes.forEach(node => {
            minX = Math.min(minX, node.x);
            maxX = Math.max(maxX, node.x);
            minY = Math.min(minY, node.y);
            maxY = Math.max(maxY, node.y);
        });

        const graphW = maxX - minX + 160;
        const graphH = maxY - minY + 160;
        const viewW = this.canvas.width / window.devicePixelRatio;
        const viewH = this.canvas.height / window.devicePixelRatio;

        const zoomX = viewW / graphW;
        const zoomY = viewH / graphH;
        this.zoom = Math.min(0.9, Math.min(zoomX, zoomY));
        if (this.zoom < 0.2) this.zoom = 0.2;

        this.panX = viewW / 2 - ((minX + maxX) / 2) * this.zoom;
        this.panY = viewH / 2 - ((minY + maxY) / 2) * this.zoom;
        this.settled = false;
        this.startLoop();
    }

    // Force physics step
    updatePhysics() {
        if (this.settled) return;

        let maxMotion = 0;

        // 1. Repulsion force between node pairs
        for (let i = 0; i < this.nodes.length; i++) {
            const nodeA = this.nodes[i];
            for (let j = i + 1; j < this.nodes.length; j++) {
                const nodeB = this.nodes[j];
                const dx = nodeB.x - nodeA.x;
                const dy = nodeB.y - nodeA.y;
                const distance = Math.sqrt(dx * dx + dy * dy) || 1;

                if (distance < 500) {
                    const force = this.repulsionConstant / (distance * distance);
                    const fx = (dx / distance) * force;
                    const fy = (dy / distance) * force;

                    if (nodeA !== this.draggedNode) {
                        nodeA.vx -= fx;
                        nodeA.vy -= fy;
                    }
                    if (nodeB !== this.draggedNode) {
                        nodeB.vx += fx;
                        nodeB.vy += fy;
                    }
                }
            }
        }

        // 2. Attraction force along edges
        this.edges.forEach(edge => {
            const dx = edge.target.x - edge.source.x;
            const dy = edge.target.y - edge.source.y;
            const distance = Math.sqrt(dx * dx + dy * dy) || 1;
            
            const force = this.springConstant * (distance - this.springLength);
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;

            if (edge.source !== this.draggedNode) {
                edge.source.vx += fx;
                edge.source.vy += fy;
            }
            if (edge.target !== this.draggedNode) {
                edge.target.vx -= fx;
                edge.target.vy -= fy;
            }
        });

        // 3. Gravity/Center pull
        const centerX = (this.canvas.width / window.devicePixelRatio) / 2;
        const centerY = (this.canvas.height / window.devicePixelRatio) / 2;
        this.nodes.forEach(node => {
            if (node === this.draggedNode) return;

            const dx = centerX - node.x;
            const dy = centerY - node.y;
            node.vx += dx * this.gravityConstant;
            node.vy += dy * this.gravityConstant;

            // Apply friction & update positions
            node.vx *= this.damping;
            node.vy *= this.damping;
            
            node.x += node.vx;
            node.y += node.vy;

            const motion = node.vx * node.vx + node.vy * node.vy;
            maxMotion = Math.max(maxMotion, motion);
        });

        // Settle condition
        if (maxMotion < 0.05 && !this.draggedNode) {
            this.settled = true;
        }
    }

    // Render Canvas frame
    draw() {
        const ctx = this.ctx;
        const width = this.canvas.width / window.devicePixelRatio;
        const height = this.canvas.height / window.devicePixelRatio;

        ctx.clearRect(0, 0, width, height);

        // Apply translation and zoom transformations
        ctx.save();
        ctx.translate(this.panX, this.panY);
        ctx.scale(this.zoom, this.zoom);

        // Draw edges
        this.edges.forEach(edge => {
            ctx.beginPath();
            ctx.moveTo(edge.source.x, edge.source.y);
            ctx.lineTo(edge.target.x, edge.target.y);
            
            // Solid/dashed lines depending on confirmation status
            ctx.strokeStyle = edge.status === 'confirmed' ? 'rgba(79, 172, 254, 0.4)' : 'rgba(100, 116, 139, 0.25)';
            ctx.lineWidth = edge.status === 'confirmed' ? 2 : 1;
            if (edge.status !== 'confirmed') {
                ctx.setLineDash([5, 5]);
            } else {
                ctx.setLineDash([]);
            }
            ctx.stroke();
            ctx.setLineDash([]);

            // Draw edge arrows
            const angle = Math.atan2(edge.target.y - edge.source.y, edge.target.x - edge.source.x);
            const arrowLength = 8;
            const arrowOffset = edge.target.radius + 2; // stop at boundary
            const arrowX = edge.target.x - arrowOffset * Math.cos(angle);
            const arrowY = edge.target.y - arrowOffset * Math.sin(angle);

            ctx.beginPath();
            ctx.moveTo(arrowX, arrowY);
            ctx.lineTo(arrowX - arrowLength * Math.cos(angle - Math.PI / 6), arrowY - arrowLength * Math.sin(angle - Math.PI / 6));
            ctx.lineTo(arrowX - arrowLength * Math.cos(angle + Math.PI / 6), arrowY - arrowLength * Math.sin(angle + Math.PI / 6));
            ctx.closePath();
            ctx.fillStyle = edge.status === 'confirmed' ? 'rgba(79, 172, 254, 0.4)' : 'rgba(100, 116, 139, 0.25)';
            ctx.fill();
        });

        // Draw nodes
        this.nodes.forEach(node => {
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
            
            // Ecosystem color coding
            let fillStyle = '#1e293b';
            let strokeStyle = '#475569';
            let shadowColor = 'transparent';

            if (node.ecosystem === 'npm') {
                fillStyle = 'rgba(239, 68, 68, 0.15)';
                strokeStyle = 'rgba(239, 68, 68, 0.6)';
                shadowColor = 'rgba(239, 68, 68, 0.2)';
            } else if (node.ecosystem === 'github') {
                fillStyle = 'rgba(6, 182, 212, 0.15)';
                strokeStyle = 'rgba(6, 182, 212, 0.6)';
                shadowColor = 'rgba(6, 182, 212, 0.2)';
            } else if (node.ecosystem === 'wayback') {
                fillStyle = 'rgba(168, 85, 247, 0.15)';
                strokeStyle = 'rgba(168, 85, 247, 0.6)';
                shadowColor = 'rgba(168, 85, 247, 0.2)';
            } else if (node.ecosystem === 'sbom') {
                fillStyle = 'rgba(59, 130, 246, 0.15)';
                strokeStyle = 'rgba(59, 130, 246, 0.6)';
                shadowColor = 'rgba(59, 130, 246, 0.2)';
            }

            // Highlighting selection
            if (this.selectedNode === node) {
                strokeStyle = '#00f2fe';
                shadowColor = 'rgba(0, 242, 254, 0.6)';
                ctx.lineWidth = 3;
            } else {
                ctx.lineWidth = 1.5;
            }

            ctx.fillStyle = fillStyle;
            ctx.fill();

            // Set borders depending on confirm status
            if (node.status !== 'confirmed') {
                ctx.setLineDash([4, 4]);
            } else {
                ctx.setLineDash([]);
            }
            ctx.strokeStyle = strokeStyle;
            ctx.stroke();
            ctx.setLineDash([]);

            // Draw text details inside node
            ctx.fillStyle = '#f8fafc';
            ctx.font = 'bold 11px Outfit, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';

            // Text Truncation
            let displayName = node.name;
            if (displayName.length > 10) displayName = displayName.slice(0, 8) + '..';
            ctx.fillText(displayName, node.x, node.y - 8);

            ctx.fillStyle = '#94a3b8';
            ctx.font = '10px Outfit, sans-serif';
            ctx.fillText(node.version, node.x, node.y + 6);

            ctx.fillStyle = '#64748b';
            ctx.font = '9px JetBrains Mono, monospace';
            ctx.fillText(node.ecosystem.toUpperCase(), node.x, node.y + 18);
        });

        ctx.restore();
    }

    startLoop() {
        if (this.loopRunning) return;
        this.loopRunning = true;
        
        const tick = () => {
            this.updatePhysics();
            this.draw();

            if (!this.settled || this.draggedNode) {
                requestAnimationFrame(tick);
            } else {
                this.loopRunning = false;
            }
        };
        requestAnimationFrame(tick);
    }

    setupEvents() {
        // Translate screen mouse coordinates to transformed graph coordinate system
        const getGraphCoords = (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            return {
                x: (x - this.panX) / this.zoom,
                y: (y - this.panY) / this.zoom
            };
        };

        this.canvas.addEventListener('mousedown', e => {
            const coords = getGraphCoords(e);
            
            // Check if node clicked
            let clickedNode = null;
            for (let i = this.nodes.length - 1; i >= 0; i--) {
                const node = this.nodes[i];
                const dx = coords.x - node.x;
                const dy = coords.y - node.y;
                if (dx * dx + dy * dy < node.radius * node.radius) {
                    clickedNode = node;
                    break;
                }
            }

            if (clickedNode) {
                this.draggedNode = clickedNode;
                this.selectedNode = clickedNode;
                this.settled = false;
                this.startLoop();
                if (this.onNodeSelected) {
                    this.onNodeSelected(clickedNode.data);
                }
            } else {
                this.isPanning = true;
                this.lastMouseX = e.clientX;
                this.lastMouseY = e.clientY;
            }
        });

        window.addEventListener('mousemove', e => {
            if (this.draggedNode) {
                const coords = getGraphCoords(e);
                this.draggedNode.x = coords.x;
                this.draggedNode.y = coords.y;
                this.draggedNode.vx = 0;
                this.draggedNode.vy = 0;
                this.settled = false;
                this.startLoop();
            } else if (this.isPanning) {
                const dx = e.clientX - this.lastMouseX;
                const dy = e.clientY - this.lastMouseY;
                this.panX += dx;
                this.panY += dy;
                this.lastMouseX = e.clientX;
                this.lastMouseY = e.clientY;
                this.draw();
            }
        });

        window.addEventListener('mouseup', () => {
            this.draggedNode = null;
            this.isPanning = false;
        });

        this.canvas.addEventListener('wheel', e => {
            e.preventDefault();
            const rect = this.canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            const graphMouseX = (mouseX - this.panX) / this.zoom;
            const graphMouseY = (mouseY - this.panY) / this.zoom;

            const zoomFactor = 1.1;
            if (e.deltaY < 0) {
                this.zoom *= zoomFactor;
            } else {
                this.zoom /= zoomFactor;
            }

            this.zoom = Math.max(0.15, Math.min(this.zoom, 5.0));

            // Adjust translation to keep mouse anchor stable
            this.panX = mouseX - graphMouseX * this.zoom;
            this.panY = mouseY - graphMouseY * this.zoom;
            this.draw();
        });

        // Handle resize
        window.addEventListener('resize', () => {
            this.resize();
        });
    }
}
window.DependencyGraphRenderer = DependencyGraphRenderer;
