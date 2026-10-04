# Local interface fonts

EveryOut loads these fonts from its bundled assets. It does not contact a font service.

- [Geist](https://github.com/google/fonts/tree/main/ofl/geist): variable UI font, `Geist.ttf`.
- [Doto](https://github.com/google/fonts/tree/main/ofl/doto): variable dot display font, `Doto.ttf`.

Both fonts are distributed under the SIL Open Font License 1.1. The complete licenses
and copyright notices are included in `Geist-OFL.txt` and `Doto-OFL.txt`.

The files were obtained from the Google Fonts repository on October 4, 2026. Geist is
used for interface text; Doto is limited to the selected-item counter. The interface
remains readable with local system fallbacks while the bundled fonts load.
