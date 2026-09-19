// The APKraken mark: a mobile "monster" — a rounded app-icon head with two eyes and a
// fanged grin, drawn as a single-color silhouette (eyes + mouth are cut-outs) so it takes
// on any color via `color` and adapts to the active theme.
export default function Logo({ size = 22, color = 'currentColor', title = 'APKraken', style, ...rest }) {
  return (
    <svg
      role="img"
      aria-label={title}
      width={size}
      height={size}
      viewBox="0 0 100 100"
      style={{ display: 'inline-block', flex: 'none', ...style }}
      {...rest}
    >
      <path
        fill={color}
        fillRule="evenodd"
        d="
          M36 20 H64 A18 18 0 0 1 82 38 V60 A18 18 0 0 1 64 78 H60 L54 88 L48 78 H36
          A18 18 0 0 1 18 60 V38 A18 18 0 0 1 36 20 Z
          M33 43 a7 7 0 1 0 14 0 a7 7 0 1 0 -14 0 Z
          M53 43 a7 7 0 1 0 14 0 a7 7 0 1 0 -14 0 Z
          M33 58 H67 V64 L60 70 L53 63 L46 70 L39 63 L33 66 Z
        "
      />
    </svg>
  );
}
