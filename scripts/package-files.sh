# Sourced by the package checks. A crate archive carries the license notice
# and exactly the committed source and test files of its crate directory.
#
# package_file_problems LABEL PACKAGED TRACKED
#   PACKAGED: sorted archive paths relative to the package root.
#   TRACKED: sorted committed paths relative to the crate directory.
# Prints one line per problem and returns nonzero if there is any.
package_file_problems() {
  local label=$1 packaged=$2 tracked=$3 status=0 line
  if ! LC_ALL=C grep -qx 'LICENSE' "$packaged"; then
    printf '%s: LICENSE is not packaged\n' "$label"
    status=1
  fi
  while IFS= read -r line; do
    case $line in
      '< '*) printf '%s: committed %s is not packaged\n' "$label" "${line#< }" ;;
      '> '*) printf '%s: packaged %s is not committed\n' "$label" "${line#> }" ;;
      *) continue ;;
    esac
    status=1
  done < <(diff <(LC_ALL=C grep -E '^(src|tests)/' "$tracked") <(LC_ALL=C grep -E '^(src|tests)/' "$packaged"))
  return "$status"
}
