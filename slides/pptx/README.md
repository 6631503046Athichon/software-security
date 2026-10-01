# Rendered PowerPoint decks (KOSEN-KMITL branded)

`week01.pptx … week19.pptx` — presentable, **KOSEN-KMITL-branded** PowerPoint decks
generated from the Marp markdown in `../weekNN.md` (the source of truth).

## Brand
- **KMITL main:** orange `#E35205` (Pantone 166c) — official CI 2022
- **KOSEN:** blue `#017BC4` (from the KOSEN-KMITL logo)
- **Neutrals (KMITL secondary):** white `#FFFFFF`, grey `#666666`, black `#000000`
- Logo: `assets/logo-small.png` (KOSEN-KMITL official, downscaled for small file size)
- Dark premium theme; logo on every slide; section icons + cards; native PPTX tables/charts.

## Regenerate (after editing the `../weekNN.md` source)
```bash
cd slides/pptx
npm install pptxgenjs react-icons react react-dom sharp   # once
node build_all.js                                         # rebuilds all 19 .pptx
```
The decks open and are fully editable in PowerPoint. Edit content in the Marp
`.md` files and re-run, or tweak the generated `.pptx` directly for one-off slides.

## Diagrams
A slide line `![alt](img/name.svg)` is **embedded as a picture**: the SVG is rasterised with `sharp` to a 1600 px
palette PNG (about 20-100 KB each) and centred at the largest size that fits between the title and the footer. The
file is looked up in the week's lab directory (`labs/weekNN-<slug>/img/`), the same place the web renderer uses; only
`img/<plain name>.svg|png|jpg` is accepted. The alt text becomes the picture's alt text and is also copied into the
speaker notes. If the file is missing or cannot be rendered, the slide falls back to a one-line
`See diagram: <alt> (web only)` pointer and the build prints a warning.
- The diagrams are dense web graphics, so on a 16:9 slide their labels are small; the 1600 px PNG stays sharp when you zoom in PowerPoint.
- A picture takes the whole slide: any bullets that follow it move to a "(cont.)" slide.
- Interactive simulations (```` ```sim ```` fences) cannot be embedded and still show a "Try it live: /sim/... (web only)" line.
- Rasterising uses the fonts installed on the machine that runs the build, so rebuild on the same machine for identical pictures.

> Size: about 8 MB for all 19 decks (the logo is a palette-quantised PNG and the diagrams are palette PNGs).
