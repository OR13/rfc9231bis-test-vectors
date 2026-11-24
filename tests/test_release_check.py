from xml.etree import ElementTree as ET
import pytest
from xmlsec_vectors.release_check import check_junit


def report(tmp_path,skip=None):
    root=ET.Element('testsuites');suite=ET.SubElement(root,'testsuite')
    for i in range(73): ET.SubElement(suite,'testcase',classname='tests.test_pq_boundaries',name=f'test_native_boundary[{i}]')
    if skip:
        case=ET.SubElement(suite,'testcase',classname=skip[0],name=skip[1]);ET.SubElement(case,'skipped',type=skip[2])
    path=tmp_path/'junit.xml';ET.ElementTree(root).write(path);return path


def test_release_gate_rejects_native_skip(tmp_path):
    with pytest.raises(RuntimeError,match='Unexpected skip'):
        check_junit(report(tmp_path,('tests.test_pq_boundaries','test_native_boundary[missing]','pytest.skip')))


def test_release_gate_rejects_ed448_not_executed(tmp_path):
    with pytest.raises(RuntimeError,match='must execute'):
        check_junit(report(tmp_path,('tests.test_native_xml','test_native_ed448_nonempty_context','pytest.skip')))


def test_release_gate_allows_known_executed_failure(tmp_path):
    assert check_junit(report(tmp_path,('tests.test_native_xml','test_native_ed448_nonempty_context','pytest.xfail')))['mandatory_native_cases']==73
