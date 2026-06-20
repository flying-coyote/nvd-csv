// nvd-csv — pull the live CVE shards from GitHub and merge them into one table.
//
// How to use in Excel (Windows):
//   1. Data tab → Get Data → From Other Sources → Blank Query
//   2. Home → Advanced Editor → delete everything → paste this whole script
//   3. Done → Close & Load   (creates a worksheet table of every CVE)
//   4. Refresh any time with Data → Refresh All
//
// It pulls the three age-band CSVs and stacks them into a single table, then
// types the score / KEV flag / date columns so you can sort and filter them.
// (Mac Excel has no Power Query; use the DuckDB/pandas examples in the README.)

let
    RawBase = "https://raw.githubusercontent.com/flying-coyote/nvd-csv/main/data/shards/",

    // The current shard files. If the bands are ever re-tuned, update this list
    // (or use the auto-discover variant at the bottom of this file).
    Shards = {
        "cve_2022_and_before.csv",
        "cve_2023_to_2025.csv",
        "cve_2026_to_now.csv"
    },

    LoadOne = (name as text) as table =>
        Table.PromoteHeaders(
            Csv.Document(
                Web.Contents(RawBase, [RelativePath = name]),
                [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]
            ),
            [PromoteAllScalars = true]
        ),

    Combined = Table.Combine(List.Transform(Shards, LoadOne)),

    Typed = Table.TransformColumnTypes(Combined, {
        {"cvss_base_score", type number},
        {"cisa_kev", Int64.Type},
        {"date_published", type date},
        {"date_updated", type date},
        {"kev_date_added", type date}
    })
in
    Typed

// ---------------------------------------------------------------------------
// AUTO-DISCOVER VARIANT — finds every shard via the GitHub API, so it keeps
// working if the bands change. Replace the `let ... in Typed` above with this.
//
// let
//     Api = "https://api.github.com/repos/flying-coyote/nvd-csv/contents/data/shards",
//     Listing = Json.Document(Web.Contents(Api, [Headers = [Accept = "application/vnd.github+json"]])),
//     Files = Table.SelectRows(Table.FromRecords(Listing), each Text.EndsWith([name], ".csv")),
//     LoadOne = (url as text) as table =>
//         Table.PromoteHeaders(
//             Csv.Document(Web.Contents(url), [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]),
//             [PromoteAllScalars = true]),
//     Combined = Table.Combine(Table.AddColumn(Files, "Data", each LoadOne([download_url]))[Data]),
//     Typed = Table.TransformColumnTypes(Combined, {
//         {"cvss_base_score", type number}, {"cisa_kev", Int64.Type},
//         {"date_published", type date}, {"date_updated", type date},
//         {"kev_date_added", type date}})
// in
//     Typed
