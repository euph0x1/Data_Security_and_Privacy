"""Tiny offline SVG sequence-diagram generator (no internet / Graphviz binary needed)."""
import html

COLORS = {"tls": "#1a73e8", "e2ee": "#188038", "plain": "#5f6368", "err": "#d93025", "sig": "#b06000"}


def sequence_svg(participants, steps, col_w=210):
    """participants: list[str]; steps: list[(from_idx, to_idx, text, kind, dashed)]"""
    n, gap, top = len(participants), 54, 70
    W = col_w * n
    H = top + gap * (len(steps) + 1)
    xs = [col_w // 2 + i * col_w for i in range(n)]
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="100%" '
         f'style="background:#fff;font-family:Arial,sans-serif">']
    for k, c in COLORS.items():
        o.append(f'<defs><marker id="a_{k}" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">'
                 f'<path d="M0,0 L10,4 L0,8 z" fill="{c}"/></marker></defs>')
    for x, p in zip(xs, participants):
        o.append(f'<rect x="{x-80}" y="10" width="160" height="38" rx="6" fill="#e8f0fe" stroke="#1a73e8"/>')
        o.append(f'<text x="{x}" y="34" text-anchor="middle" font-size="13" font-weight="bold" fill="#202124">{html.escape(p)}</text>')
        o.append(f'<line x1="{x}" y1="48" x2="{x}" y2="{H-8}" stroke="#9aa0a6" stroke-dasharray="4 4"/>')
    for i, st in enumerate(steps):
        a, b, text, kind = st[:4]
        dashed = st[4] if len(st) > 4 else False
        y = top + gap * (i + 1) - 14
        c = COLORS.get(kind, "#5f6368")
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        if a == b:
            x = xs[a]
            o.append(f'<path d="M{x},{y-10} h46 v22 h-46" fill="none" stroke="{c}" stroke-width="1.6" marker-end="url(#a_{kind})"/>')
            o.append(f'<text x="{x+54}" y="{y+6}" font-size="12" fill="{c}">{html.escape(text)}</text>')
        else:
            x1, x2 = xs[a], xs[b]
            o.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{c}" stroke-width="1.8"{dash} marker-end="url(#a_{kind})"/>')
            o.append(f'<text x="{(x1+x2)//2}" y="{y-6}" text-anchor="middle" font-size="12" fill="{c}">{html.escape(text)}</text>')
    o.append("</svg>")
    return "".join(o), H


def show_svg(svg: str):
    """Render SVG in Streamlit (base64 <img> works on every Streamlit version)."""
    import base64
    import streamlit as st
    b = base64.b64encode(svg.encode()).decode()
    st.markdown(f'<img style="width:100%" src="data:image/svg+xml;base64,{b}"/>', unsafe_allow_html=True)
