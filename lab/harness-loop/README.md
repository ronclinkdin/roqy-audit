# harness-loop: לולאת שיפור בסגנון Harness² ל-roqy-audit

זו לולאה שמשפרת את הבדיקות של האודיט מול המעבדה ב-sandbox, בלי Vertex AI ובלי מודל חובה. כל סבב עושה Propose, Probe ו-Compose: מציע שינויים, מריץ את האודיט האמיתי מול המעבדה, ושומר רק מה שבאמת שיפר את הציון בלי להעלות false positives.

## איך זה בנוי

| קובץ | תפקיד |
|---|---|
| `loop.py` | המנהל של הסבבים: baseline, הצעות, בדיקה של כל הצעה, הרכבה, אימות live ו-commit |
| `proposer/propose.py` | ה-Propose. היוריסטיקות דטרמיניסטיות, ורואה רק את `feedback.json` המסונן |
| `proposer/llm_hook.py` | נקודת חיבור למודל (כרגע stub). אפשר לחבר כל סקריפט שמקבל JSON ב-stdin ומחזיר רשימת edits |
| `probe.py` | ה-Probe. מריץ את `audit_v3.py` ואת `audit_envelope.py` דרך ה-role לקריאה בלבד, אוסף זמנים וספירת קריאות API, ומפעיל את ה-grader |
| `grader/grade.py` | הרכיב היחיד שקורא את `EXPECTED-FINDINGS.yaml` (דרך `score.py`) |
| `grader/known-unplanted.yaml` | ממצאים אמיתיים על משאבי המעבדה שלא נשתלו בכוונה (true-positive-unplanted), למשל פורט 22 שנפתח ידנית ב-roqy-lab-client-web |
| `guard.py` + `surface/guardrails.yaml` | אכיפה בקוד, לפני כל קריאת aws, kubectl או helm |
| `overlay.py` + `surface/checks-overlay.yaml` | המשטח שהלולאה עורכת: severity לכל בדיקה, כיבוי בדיקה ו-knobs |
| `surface/knob-catalog.yaml` | אילו knobs מותר להזיז ולאילו ערכים. ערך שלא מופיע כאן נדחה |
| `surface/prompt.md` | טקסט ה-guardrails וה-prompt של הסוכן. שורות שהלולאה מציעה נרשמות, אבל נכנסות רק כשמחברים executor של LLM שיכול לנקד אותן |
| `variants/clean-repo/` | תאום מוקשח של ה-client-repo. כל ממצא שם נחשב false positive |
| `config.yaml` | הווריאנטים: `full` (המעבדה), `clean-repo`, `clean-account` (placeholder לחשבון נקי) ו-`scale` (placeholder לכל ה-regions) |
| `runs/` | כל ריצה, `REPORT.md` לכל loop, ו-`ledger.jsonl` עם כל הצעה וכל commit |

## למה ה-grader מוסתר

ה-proposer לא רואה את קובץ התשובות. הוא מקבל רק ציון לכל קטגוריה, tokens אטומים לכל miss (hash עם salt) עם ה-check id הצפוי, ואת ה-severity שהבדיקה **הוציאה**, לא את מה שציפינו. בנוסף הוא מקבל ספירת FP לכל בדיקה, permission gaps ומספרי scale. זה נאכף בשלוש שכבות:
- **audit hook ב-Python:** תהליך ה-proposer לא יכול לפתוח את `EXPECTED-FINDINGS`, את `grader/` או את `private/`.
- **בדיקת דליפה ב-grader:** אם שם של plant או של משאב נכנס ל-feedback, ה-grader עוצר.
- **טסטים:** `tests/test_no_leak.py`.

לכן כשיש severity mismatch, ה-proposer לא יודע מה הערך הנכון. הוא מציע את כל הרמות האחרות, וה-Probe מחליט.

## חוקי ה-Compose

הצעה מתקבלת רק אם ה-detected לא ירד, ואם ה-severity mismatch, ה-FP בווריאנטים הנקיים וה-untriaged unmatched לא עלו. בנוסף אסור שיהיו guard violations, וה-objective צריך לעלות בפועל:
`10·detected − 3·sev_mismatch − 5·clean_fp − 2·untriaged − 50·guard_violations`.

את ההצעות בודקים במצב replay. ה-core עונה מה-cache של ה-raw של ריצת ה-baseline, ולכן כל הצעה לוקחת כ-25 שניות ולא כ-2.5 דקות. אחר כך ההרכבה של כל ההצעות שהתקבלו עוברת אימות **live** מול המעבדה, ורק אז נכתבת ל-`surface/`. שינוי severity מסונכרן גם ל-`lab/lab-run/checks-v3.yaml`.

את `guardrails.yaml` הלולאה יכולה רק להדק. כל הרחבה נדחית, וגם הוספת הרשאות IAM לא נעשית אוטומטית: היא נרשמת כ-`decision` לאישור אנושי.

## הרצה

```bash
cd lab/harness-loop   # from the repo root
python3 -m pytest -q tests                      # guard + בידוד ה-grader
python3 probe.py --run runs/baseline-live       # baseline live (~2.6 דק')
python3 loop.py --iterations 3 --baseline-run runs/baseline-live
```

כדי לחבר מודל, מגדירים ב-`config.yaml` את `llm.provider: command` ואת `llm.command: "python3 my_proposer.py"`. זה יכול להיות Ollama מקומי, Claude או OpenAI. המודל מקבל בדיוק את אותו feedback מסונן.

## הסבב הראשון (2026-11-04)

ה-baseline היה 94/94 detected, mismatch אחד (W7 הוציא P1) ו-FP אחד ב-clean-repo. ה-FP הוא NEW-CICD-PR-APPLY, שסימן workflow שבו ה-apply רץ רק ב-push ל-main. היו 4 הצעות, 2 התקבלו:
- **`W7.severity = P2`:** ה-P0 וה-P3 נדחו.
- **`NEW-CICD-PR-APPLY.scope = job`:** הבדיקה בודקת עכשיו את ה-`if:` ברמת ה-job.

אחרי אימות live: 94/94, אפס mismatch ואפס FP, וה-objective עלה מ-932 ל-940. בסבב השני לא היו הצעות, אז הלולאה עצרה.

## מה עוד פתוח
- `clean-account`: צריך חשבון AWS נקי שני ופרופיל `roqy-audit-clean`, ואז `enabled: true`.
- ה-cache של ה-replay שומר raw outputs, שיכולים לכלול ערכים של env ב-Lambda או ב-ECS. במעבדה הערכים מזויפים, אבל ללקוח אמיתי צריך להשחיר אותם לפני שמירה.
- ה-core רץ באופן סדרתי (169 קריאות ב-130 שניות על 2 regions). ב-scale צריך מקביליות של regions, עד 4.
