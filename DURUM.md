# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — CI gating için `--fail-on-unsafe` eklendi

- Konu: `--fail-on-unsafe` bayrağı eklendi — `safe_to_return` False ise çıkış kodu 1 (bir yanıtı kullanıcıya döndürmeden önce veya regresyon testinde kullanılabilir). `main()` artık `int` dönüyor, `sys.exit(main())` ile çağrılıyor.
- 3 yeni test eklendi (8 → 11), hepsi geçti. Ruff temiz.
- Durum: ✅ Henüz push edilmedi.

**Sıradaki iş:** GitHub'da `LLM-Output-Guardrail` adıyla repo aç, git init + push.

---

## 2026-08-20 — Paketleme, JSON çıktı ve lint eklendi

- Konu: `pyproject.toml` ile pip kurulabilir hale getirildi (`pip install -e .` → `llm-output-guardrail` komutu), `--format json` eklendi, ruff lint + CI'a ayrı bir lint job'u eklendi.
- Durum: ✅ 8/8 test geçiyor (2 yeni JSON testi dahil), ruff temiz, `pip install -e .` ile gerçek kurulum + CLI çalıştırma + `pip uninstall` doğrulandı.

**Sıradaki iş:** GitHub'da `LLM-Output-Guardrail` adıyla repo aç, git init + push.

---

## 2026-08-20 — İlk sürüm oluşturuldu

- Konu: LLM çıktılarında PII/secret/policy-violation sızıntısı tespit eden ve maskeleyen guardrail kütüphanesi + CLI hazırlandı. `LLM-Prompt-Injection-Test-Kit` projesinin doğal tamamlayıcısı (input tarafı orada, output tarafı burada).
- Test: 6/6 pytest testi geçti. 3 örnek çıktı (clean/pii_leak/secret_leak) gerçekten tarandı, `sample_report.md` bu gerçek çalıştırmadan üretildi.
- Durum: ✅ Çalışıyor, test edildi, CI eklendi.

**Sıradaki iş:** GitHub'da `LLM-Output-Guardrail` adıyla repo aç, git init + push. `LLM-Prompt-Injection-Test-Kit` ile birlikte ikili olarak sunulabilir.
