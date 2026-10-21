#!/usr/bin/env python3
"""Optional offline browser acceptance. Requires Playwright and Chromium locally."""
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1600, 'height': 1000})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto((ROOT / 'AI-Agent安全审计图谱.html').as_uri())
    page.wait_for_selector('[data-open="object:A5.2"]')
    for kind, ident in [('risk', 'LLM01'), ('object', 'A5.2'), ('security', 'X2.3'), ('layer', 'A5'), ('domain', 'X2')]:
        selector = f'button[data-toggle-selection][data-open="{kind}:{ident}"]'
        page.locator(selector).first.click()
        assert page.evaluate('AgentExplorer.getState().selection') == {'kind': kind, 'id': ident}
        page.locator('#detail-close').click()
        page.locator(selector).first.click()
        assert page.evaluate('AgentExplorer.getState().selection') is None, (kind, ident)
    page.locator('[data-open="object:A5.2"]').first.click()
    page.locator('[data-tab="risks"]').click()
    fm = page.locator('[data-fm-id="FM-A5.2-03"]')
    fm.locator('summary').click()
    assert '适用前提' in fm.inner_text() and '失效判据' in fm.inner_text()
    assert '记忆服务为多个主体复用' in fm.inner_text()
    page.locator('#detail-close').click()
    tooltip = page.locator('[data-open="object:A5.2"]').first.locator('xpath=..').locator('.risk-tag').first.get_attribute('title')
    assert '适用前提' in tooltip and '失效判据' in tooltip
    page.evaluate("AgentExplorer.open('risk', 'LLM01')")
    page.locator('[data-tab="objects"]').click()
    assert '适用前提' in page.locator('#detail-content').inner_text()
    assert '失效判据' in page.locator('#detail-content').inner_text()
    # Every object's proposition panel renders without missing-schema errors.
    all_objects = page.evaluate('Object.entries({...AgentExplorer.data.objects,...AgentExplorer.data.security_objects,...AgentExplorer.data.security_views}).map(([id,o])=>[id,id.startsWith("A")?"object":"security",o.failure_mode_ids.length])')
    for ident, kind, count in all_objects:
        page.evaluate('([kind,id])=>AgentExplorer.open(kind,id)', [kind, ident])
        page.locator('[data-tab="risks"]').click()
        assert page.locator('.failure-mode').count() == count, ident
    # A risk can reach two independent propositions on the same object.
    page.evaluate("AgentExplorer.open('object','A4.1')")
    page.locator('[data-tab="risks"]').click()
    for fid, role in [('FM-A4.1-01', '入口'), ('FM-A4.1-05', '风险定位')]:
        card = page.locator(f'.failure-mode[data-fm-id="{fid}"]')
        for rid in ['MCP03', 'ASI04']:
            assert card.locator(f'[data-open="risk:{rid}"] .mapping-role').inner_text() == role
    page.locator('#detail-close').click()
    directory = page.locator('[data-open="object:A4.1"]').first.locator('xpath=..')
    # Expand the card's risk tags when the MCP entry is initially below the fold.
    more = directory.locator('[data-expand="A4.1"]')
    if more.count():
        more.click()
    tooltip = directory.locator('[data-risk-tag="MCP03"]').get_attribute('title')
    assert 'FM-A4.1-01' in tooltip and 'FM-A4.1-05' in tooltip
    page.evaluate("AgentExplorer.open('risk','MCP03')")
    page.locator('[data-tab="objects"]').click()
    for oid, fids in [('A4.1', ['FM-A4.1-01', 'FM-A4.1-05']),
                      ('A4.3', ['FM-A4.3-02', 'FM-A4.3-04'])]:
        rows = page.locator(f'.link-box[data-object-id="{oid}"]')
        assert rows.count() == len(fids), oid
        for fid in fids:
            assert page.locator(f'.link-box[data-object-id="{oid}"][data-fm-id="{fid}"]').count() == 1
    page.locator('[data-tab="sources"]').click()
    assert page.locator('a[href*="/blob/c11a8527312b9468aadb76ad0df3572f6da40c47/"]').count() >= 3
    # The preview's "show more" button must also expand the object overview.
    candidate = page.evaluate('Object.keys(AgentExplorer.data.objects).find(id=>Object.values(AgentExplorer.data.cases).filter(c=>c.object_ids.includes(id)).length>2)')
    page.evaluate('(id)=>AgentExplorer.open("object",id)', candidate)
    before = page.locator('#detail-content .case-card').count()
    page.locator('[data-more-cases]').click()
    assert page.locator('#detail-content .case-card').count() > before
    # A risk family must be navigable, not merely embedded in the JSON payload.
    mcp_group = page.locator('[data-family-group="MCP"]')
    assert mcp_group.locator('button.risk-item').count() == 10
    assert mcp_group.evaluate("(el)=>getComputedStyle(el).getPropertyValue('--family').trim()")
    assert '61OWASP风险' in page.locator('#statistics').inner_text().replace(' ', '').replace('\n', '')
    for number in range(1, 11):
        rid = f'MCP{number:02d}'
        page.evaluate('(id)=>AgentExplorer.open("risk",id)', rid)
        assert '2025' in page.locator('#detail-kicker').inner_text()
        assert 'beta' in page.locator('#detail-kicker').inner_text()
        for tab in ['overview', 'objects', 'controls', 'cases', 'sources']:
            page.locator(f'[data-tab="{tab}"]').click()
            assert page.locator('#detail-content').inner_text().strip(), (rid, tab)
        assert 'v0.1' in page.locator('#detail-content').inner_text()
        assert page.locator('#detail-content a[href*="/blob/165fe0f78"]').count() > 0
    page.evaluate("AgentExplorer.open('risk','MCP06')")
    page.locator('[data-tab="sources"]').click()
    assert 'Intent Flow Subversion' in page.locator('#detail-content').inner_text()
    assert 'Prompt Injection via Contextual Payloads' in page.locator('#detail-content').inner_text()
    page.evaluate("AgentExplorer.open('risk','MCP05')")
    page.locator('[data-tab="cases"]').click()
    assert page.locator('[data-case-id="PUB-047"]').count() == 1
    page.evaluate("AgentExplorer.open('object','A6.1')")
    page.locator('[data-tab="risks"]').click()
    page.locator('[data-fm-id="FM-A6.1-05"] [data-open="risk:MCP08"]').click()
    assert 'MCP08' in page.locator('#detail-kicker').inner_text()
    page.evaluate("AgentExplorer.open('sources','overview')")
    source_text = page.locator('#detail-content').inner_text()
    assert 'OWASP MCP Top 10' in source_text
    assert 'CC BY-NC-SA 4.0' in source_text
    assert not errors, errors
    browser.close()
    print(f'PASS: selection toggles, {len(all_objects)} object panels, case expansion, and all 10 MCP risks with sources')
