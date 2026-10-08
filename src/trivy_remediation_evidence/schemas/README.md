# スキーマの読み方

JSON Schema Draft 2020-12。外部参照なし。manifest/report は入力、evidence は出力。
reason-catalog.jsonはスキーマではなく、機械コードに対するJA/EN固定文言辞書。
Schema検証だけでは比較可能にならない。DESIGN.ja.mdの意味ゲート・理由コードが規範。
report.schema.jsonは公式report全体のコピーではなく、このCLIが必要とする受理subset。
findingのidentity必須情報は意味検証で扱い、欠落findingも比較不可の候補として保持する。
manifestは各runに1つ。role vuln必須、DB role重複禁止、scope logicalTargetId重複禁止。
rawTargetは一run内で一意、report Results.Targetとの1対1対応を要求する。
asset.logicalIdは各asset配列内で一意。配列設定値の重複禁止。
pathのschema regexに加え、各segment検証を必須とする。
evidence sourcesの順序はbefore-report / before-manifest / after-report / after-manifest。
evidenceのsummaryはitemsのclassification別集計。比較不可時はnew/persistent/not_detected=0。
comparison=comparable iff globalReasons=[]かつ全itemsが比較不可以外。
比較可能時newはbefore=[]/after=1、persistentは各1、not_detectedはbefore=1/after=[]。
全gate診断はglobalReasonsに含める。itemのidentity局所理由もglobal gateを落とす。
JSON Schemaはこれらcross-field条件を表現しきらないため、意味検証が必須。
追加設定extraOptionsに秘密情報/認証値を入れない。認証情報は比較に必要ない。
DB updatedAt/repository/ociDigestは記録のみで比較キーではない。実snapshot hashとrole集合を比較する。
設定assetの比較キーはlogicalId/contentSha256/appliedRulesSha256。
scanner.versionは実運用では取得した完全version文字列、fixtureだけ架空版。
