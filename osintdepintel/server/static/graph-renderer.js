/**
 * DependencyGraphRenderer — force-directed canvas graph.
 * Defers layout until the canvas has a real size (hidden tab safe).
 */
class DependencyGraphRenderer {
    constructor(canvasId, onNodeSelected) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.onNodeSelected = onNodeSelected;

        this.nodes = [];
        this.edges = [];
        this.nodesMap = new Map();
        this.pending = null; // {nodesData, edgesData} until first real size

        this.zoom = 1;
        this.panX = 0;
        this.panY = 0;

        this.draggedNode = null;
        this.selectedNode = null;
        this.isPanning = false;
        this.lastMouseX = 0;
        this.lastMouseY = 0;
        this.loopRunning = false;
        this.settled = false;
        this.needsFit = false;

        this.repulsionConstant = 4000;
        this.springConstant = 0.08;
        this.springLength = 140;
        this.gravityConstant = 0.025;
        this.damping = 0.85;

        this.setupEvents();
        this._observeSize();
        this.resize();
    }

    _observeSize() {
        if (typeof ResizeObserver === 'undefined') return;
        this._ro = new ResizeObserver(() => {
            // Pane just became visible or layout changed
            this.resize();
            if (this.pending) {
                const p = this.pending;
                this.pending = null;
                this.setData(p.nodesData, p.edgesData);
            } else if (this.nodes.length) {
                this.fitToScreen();
                this.startLoop();
            }
        });
        this._ro.observe(this.canvas.parentElement || this.canvas);
    }

    _viewSize() {
        const dpr = window.devicePixelRatio || 1;
        return {
            w: this.canvas.width / dpr,
            h: this.canvas.height / dpr,
            dpr
        };
    }

    setData(nodesData, edgesData) {
        nodesData = nodesData || {};
        edgesData = edgesData || [];

        const { w, h } = this._viewSize();
        // Canvas still hidden (0×0) — stash and wait for ResizeObserver / resize
        if (w < 10 || h < 10) {
            this.pending = { nodesData, edgesData };
            this.nodes = [];
            this.edges = [];
            this.nodesMap.clear();
            return;
        }
        this.pending = null;

        this.nodes = [];
        this.edges = [];
        this.nodesMap.clear();
        this.selectedNode = null;
        this.settled = false;

        const entries = Object.entries(nodesData);
        const n = entries.length;
        const cx = w / 2;
        const cy = h / 2;

        entries.forEach(([key, record], i) => {
            // Ring layout so multi-node graphs start spread out; single node at center
            const angle = n === 1 ? 0 : (i / n) * Math.PI * 2 - Math.PI / 2;
            const radius = n === 1 ? 0 : Math.min(w, h) * 0.28;
            const node = {
                key,
                name: record.name || key,
                ecosystem: String(record.ecosystem || 'unknown').toLowerCase(),
                version: record.version || 'unknown',
                status: record.status || 'inferred',
                confidence: typeof record.confidence === 'number' ? record.confidence : 0,
                x: cx + Math.cos(angle) * radius,
                y: cy + Math.sin(angle) * radius,
                vx: 0,
                vy: 0,
                radius: n === 1 ? 52 : 36,
                data: record
            };
            this.nodes.push(node);
            this.nodesMap.set(key, node);
        });

        edgesData.forEach(edge => {
            const source = this.nodesMap.get(edge.parent_key);
            const target = this.nodesMap.get(edge.child_key);
            if (source && target) {
                this.edges.push({
                    source,
                    target,
                    status: edge.status,
                    confidence: edge.confidence
                });
            }
        });

        // Run the force layout to completion off-screen, then fit — so the graph
        // appears already settled and centred instead of visibly animating and
        // snapping into place.
        this._presettle();
        this._applyFit();
        this.draw();
    }

    // Advance the force simulation to rest without painting each frame.
    _presettle(maxIter = 600) {
        if (this.nodes.length <= 1) { this.settled = true; return; }
        this.settled = false;
        for (let i = 0; i < maxIter && !this.settled; i++) {
            this.updatePhysics();
        }
        this.settled = true;
    }

    resize() {
        if (!this.canvas) return;
        const parent = this.canvas.parentElement;
        if (!parent) return;
        const rect = parent.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        const w = Math.max(0, Math.floor(rect.width));
        const h = Math.max(0, Math.floor(rect.height));
        if (w < 1 || h < 1) return;

        // Only reset bitmap when size actually changes (avoids wiping mid-drag)
        if (this.canvas.width !== w * dpr || this.canvas.height !== h * dpr) {
            this.canvas.width = w * dpr;
            this.canvas.height = h * dpr;
            this.canvas.style.width = w + 'px';
            this.canvas.style.height = h + 'px';
            this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }

        if (this.pending && w >= 10 && h >= 10) {
            const p = this.pending;
            this.pending = null;
            this.setData(p.nodesData, p.edgesData);
            return;
        }

        if (this.nodes.length) this.draw();
    }

    // Compute pan/zoom to frame all nodes and repaint. Does NOT touch `settled`,
    // so it can be used both for an explicit fit and for a one-shot fit once the
    // force layout has settled (see startLoop).
    _applyFit() {
        if (!this.nodes.length) return false;
        const { w: viewW, h: viewH } = this._viewSize();
        if (viewW < 10 || viewH < 10) return false;

        let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
        this.nodes.forEach(node => {
            minX = Math.min(minX, node.x - node.radius);
            maxX = Math.max(maxX, node.x + node.radius);
            minY = Math.min(minY, node.y - node.radius);
            maxY = Math.max(maxY, node.y + node.radius);
        });

        const pad = 80;
        const graphW = Math.max(maxX - minX + pad * 2, 120);
        const graphH = Math.max(maxY - minY + pad * 2, 120);

        this.zoom = Math.min(1.4, Math.min(viewW / graphW, viewH / graphH));
        this.zoom = Math.max(0.25, this.zoom);

        const midX = (minX + maxX) / 2;
        const midY = (minY + maxY) / 2;
        this.panX = viewW / 2 - midX * this.zoom;
        this.panY = viewH / 2 - midY * this.zoom;
        this.draw();
        return true;
    }

    fitToScreen() {
        // Re-centre the view on the current (already settled) node positions.
        // Does not restart the simulation, so there is no visible movement.
        this._applyFit();
    }

    updatePhysics() {
        if (this.settled || this.nodes.length <= 1) {
            this.settled = true;
            return;
        }

        let maxMotion = 0;

        for (let i = 0; i < this.nodes.length; i++) {
            const a = this.nodes[i];
            for (let j = i + 1; j < this.nodes.length; j++) {
                const b = this.nodes[j];
                const dx = b.x - a.x;
                const dy = b.y - a.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                if (dist > 600) continue;
                const force = this.repulsionConstant / (dist * dist);
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;
                if (a !== this.draggedNode) { a.vx -= fx; a.vy -= fy; }
                if (b !== this.draggedNode) { b.vx += fx; b.vy += fy; }
            }
        }

        this.edges.forEach(edge => {
            const dx = edge.target.x - edge.source.x;
            const dy = edge.target.y - edge.source.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = this.springConstant * (dist - this.springLength);
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            if (edge.source !== this.draggedNode) { edge.source.vx += fx; edge.source.vy += fy; }
            if (edge.target !== this.draggedNode) { edge.target.vx -= fx; edge.target.vy -= fy; }
        });

        const { w, h } = this._viewSize();
        const cx = w / 2, cy = h / 2;
        this.nodes.forEach(node => {
            if (node === this.draggedNode) return;
            node.vx += (cx - node.x) * this.gravityConstant;
            node.vy += (cy - node.y) * this.gravityConstant;
            node.vx *= this.damping;
            node.vy *= this.damping;
            node.x += node.vx;
            node.y += node.vy;
            maxMotion = Math.max(maxMotion, node.vx * node.vx + node.vy * node.vy);
        });

        if (maxMotion < 0.04 && !this.draggedNode) this.settled = true;
    }

    draw() {
        if (!this.ctx) return;
        const { w, h } = this._viewSize();
        if (w < 1 || h < 1) return;

        const ctx = this.ctx;
        ctx.save();
        ctx.setTransform((window.devicePixelRatio || 1), 0, 0, (window.devicePixelRatio || 1), 0, 0);
        ctx.clearRect(0, 0, w, h);

        // Empty state
        if (!this.nodes.length) {
            ctx.fillStyle = '#64748b';
            ctx.font = '14px Outfit, system-ui, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(
                this.pending ? 'Waiting for layout…' : 'No dependency nodes in this report',
                w / 2, h / 2
            );
            ctx.restore();
            return;
        }

        ctx.translate(this.panX, this.panY);
        ctx.scale(this.zoom, this.zoom);

        // Edges
        this.edges.forEach(edge => {
            ctx.beginPath();
            ctx.moveTo(edge.source.x, edge.source.y);
            ctx.lineTo(edge.target.x, edge.target.y);
            const confirmed = edge.status === 'confirmed';
            ctx.strokeStyle = confirmed ? 'rgba(79, 172, 254, 0.7)' : 'rgba(148, 163, 184, 0.45)';
            ctx.lineWidth = confirmed ? 2.5 : 1.5;
            ctx.setLineDash(confirmed ? [] : [6, 5]);
            ctx.stroke();
            ctx.setLineDash([]);

            const angle = Math.atan2(edge.target.y - edge.source.y, edge.target.x - edge.source.x);
            const tip = edge.target.radius + 2;
            const ax = edge.target.x - tip * Math.cos(angle);
            const ay = edge.target.y - tip * Math.sin(angle);
            const al = 10;
            ctx.beginPath();
            ctx.moveTo(ax, ay);
            ctx.lineTo(ax - al * Math.cos(angle - Math.PI / 6), ay - al * Math.sin(angle - Math.PI / 6));
            ctx.lineTo(ax - al * Math.cos(angle + Math.PI / 6), ay - al * Math.sin(angle + Math.PI / 6));
            ctx.closePath();
            ctx.fillStyle = ctx.strokeStyle;
            ctx.fill();
        });

        // Nodes — high-contrast fills so bubbles are obvious on dark bg
        this.nodes.forEach(node => {
            const palette = {
                npm: { fill: 'rgba(239, 68, 68, 0.55)', stroke: '#f87171', glow: 'rgba(239, 68, 68, 0.55)' },
                github: { fill: 'rgba(6, 182, 212, 0.55)', stroke: '#22d3ee', glow: 'rgba(6, 182, 212, 0.55)' },
                wayback: { fill: 'rgba(168, 85, 247, 0.55)', stroke: '#c084fc', glow: 'rgba(168, 85, 247, 0.55)' },
                sbom: { fill: 'rgba(59, 130, 246, 0.55)', stroke: '#60a5fa', glow: 'rgba(59, 130, 246, 0.55)' },
                pypi: { fill: 'rgba(250, 204, 21, 0.5)', stroke: '#facc15', glow: 'rgba(250, 204, 21, 0.5)' },
            };
            const c = palette[node.ecosystem] || { fill: 'rgba(100, 116, 139, 0.6)', stroke: '#94a3b8', glow: 'rgba(148, 163, 184, 0.5)' };
            const selected = this.selectedNode === node;

            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            ctx.shadowColor = selected ? 'rgba(0, 242, 254, 0.9)' : c.glow;
            ctx.shadowBlur = selected ? 28 : 18;
            ctx.fillStyle = c.fill;
            ctx.fill();
            ctx.shadowBlur = 0;

            ctx.lineWidth = selected ? 3.5 : 2.5;
            ctx.strokeStyle = selected ? '#00f2fe' : c.stroke;
            ctx.setLineDash(node.status === 'confirmed' ? [] : [5, 4]);
            ctx.stroke();
            ctx.setLineDash([]);

            // Text
            let name = node.name;
            if (name.length > 12) name = name.slice(0, 10) + '…';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = '#ffffff';
            ctx.font = 'bold 12px Outfit, system-ui, sans-serif';
            ctx.fillText(name, node.x, node.y - 10);
            ctx.fillStyle = '#e2e8f0';
            ctx.font = '11px Outfit, system-ui, sans-serif';
            ctx.fillText(String(node.version), node.x, node.y + 6);
            ctx.fillStyle = '#cbd5e1';
            ctx.font = '10px JetBrains Mono, monospace';
            ctx.fillText(node.ecosystem.toUpperCase(), node.x, node.y + 20);
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
        const getGraphCoords = (e) => {
            const rect = this.canvas.getBoundingClientRect();
            return {
                x: (e.clientX - rect.left - this.panX) / this.zoom,
                y: (e.clientY - rect.top - this.panY) / this.zoom
            };
        };

        this.canvas.addEventListener('mousedown', e => {
            const coords = getGraphCoords(e);
            let clicked = null;
            for (let i = this.nodes.length - 1; i >= 0; i--) {
                const n = this.nodes[i];
                const dx = coords.x - n.x, dy = coords.y - n.y;
                if (dx * dx + dy * dy <= n.radius * n.radius) { clicked = n; break; }
            }
            if (clicked) {
                this.draggedNode = clicked;
                this.selectedNode = clicked;
                this.settled = false;
                this.startLoop();
                if (this.onNodeSelected) this.onNodeSelected(clicked.data);
            } else {
                this.isPanning = true;
                this.lastMouseX = e.clientX;
                this.lastMouseY = e.clientY;
            }
        });

        window.addEventListener('mousemove', e => {
            if (this.draggedNode) {
                const c = getGraphCoords(e);
                this.draggedNode.x = c.x;
                this.draggedNode.y = c.y;
                this.draggedNode.vx = 0;
                this.draggedNode.vy = 0;
                this.settled = false;
                this.startLoop();
            } else if (this.isPanning) {
                this.panX += e.clientX - this.lastMouseX;
                this.panY += e.clientY - this.lastMouseY;
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
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;
            const gx = (mx - this.panX) / this.zoom;
            const gy = (my - this.panY) / this.zoom;
            const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
            this.zoom = Math.max(0.15, Math.min(5, this.zoom * factor));
            this.panX = mx - gx * this.zoom;
            this.panY = my - gy * this.zoom;
            this.draw();
        }, { passive: false });

        window.addEventListener('resize', () => this.resize());
    }
}
window.DependencyGraphRenderer = DependencyGraphRenderer;
