import type { Category } from "./api";
import DotIcon from "./DotIcon";
import type { DotIconName } from "./DotIcon";
import { categories } from "./wipe";
import { shortCategoryNames } from "./strings";
const icons: Record<Category, DotIconName> = {
  application: "apps",
  browser: "browser",
  "windows-microsoft-and-dev-tools": "accounts",
};

export default function CategorySummary({
  counts,
  statuses,
  active = false,
}: {
  counts: Record<Category, number>;
  statuses?: Partial<Record<Category, string>>;
  active?: boolean;
}) {
  return (
    <ul
      className="category-summary"
      aria-label={
        active
          ? "Cleanup progress by category"
          : "Selected local accounts by category"
      }
    >
      {categories.map((category) => (
        <li key={category}>
          <DotIcon name={icons[category]} size={32} />
          <div>
            <span className="category-name">
              {shortCategoryNames[category]}
            </span>
            <span className="category-detail">
              {statuses?.[category] ?? `${counts[category]} selected`}
            </span>
          </div>
          <span className="category-count">
            {String(counts[category]).padStart(2, "0")}
          </span>
        </li>
      ))}
    </ul>
  );
}
