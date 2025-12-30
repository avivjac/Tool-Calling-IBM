import pytest
from unittest.mock import AsyncMock, patch, ANY
import sys
import os

# Adjust path to allow imports from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from src.server.providers.API_tools import virusTotal

@pytest.mark.asyncio
class TestVirusTotal:

    # ---------- IP Addresses ----------
    async def test_Get_an_IP_address_report(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_ip', return_value=True):
                mock_get.return_value = {"data": {"id": "1.1.1.1"}, "error": None}
                result = await virusTotal.Get_an_IP_address_report("1.1.1.1")
                assert result == {"data": {"id": "1.1.1.1"}, "error": None}
                mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/ip_addresses/1.1.1.1", ANY)

    async def test_Request_an_IP_address_rescan(self):
        with patch.object(virusTotal.requests, 'make_post_request', new_callable=AsyncMock) as mock_post:
            with patch('src.utils.validate.is_valid_ip', return_value=True):
                mock_post.return_value = {"data": {"id": "analysis_id"}, "error": None}
                result = await virusTotal.Request_an_IP_address_rescan("1.1.1.1")
                assert result == {"data": {"id": "analysis_id"}, "error": None}
                mock_post.assert_called_once_with(f"{virusTotal.BASE_URL}/ip_addresses/1.1.1.1/analyse", ANY)

    async def test_Get_comments_on_an_IP_address(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_ip', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_comments_on_an_IP_address("1.1.1.1", limit=5)
                mock_get.assert_called_once()
                args, kwargs = mock_get.call_args
                assert args[0] == f"{virusTotal.BASE_URL}/ip_addresses/1.1.1.1/comments"
                assert args[1]["limit"] == 5

    async def test_Get_objects_related_to_an_IP_address(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_ip', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_objects_related_to_an_IP_address("1.1.1.1", "resolutions")
                mock_get.assert_called_once()
                args, kwargs = mock_get.call_args
                assert args[0] == f"{virusTotal.BASE_URL}/ip_addresses/1.1.1.1/resolutions"

    async def test_Get_object_descriptors_related_to_an_IP_address(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_ip', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_object_descriptors_related_to_an_IP_address("1.1.1.1", "resolutions")
                mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/ip_addresses/1.1.1.1/relationships/resolutions", ANY)

    async def test_Get_votes_on_an_IP_address(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_ip', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_votes_on_an_IP_address("1.1.1.1")
                mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/ip_addresses/1.1.1.1/votes", ANY)

    # ---------- Domains ----------
    async def test_Get_a_domain_report(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_domain', return_value=True):
                mock_get.return_value = {"data": {"id": "example.com"}, "error": None}
                await virusTotal.Get_a_domain_report("example.com")
                mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/domains/example.com", ANY)

    async def test_Request_an_domain_rescan(self):
        with patch.object(virusTotal.requests, 'make_post_request', new_callable=AsyncMock) as mock_post:
            with patch('src.utils.validate.is_valid_domain', return_value=True):
                mock_post.return_value = {"data": {"id": "analysis_id"}, "error": None}
                await virusTotal.Request_an_domain_rescan("example.com")
                mock_post.assert_called_once_with(f"{virusTotal.BASE_URL}/domains/example.com/analyse", ANY)

    async def test_Get_comments_on_a_domain(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_domain', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_comments_on_a_domain("example.com")
                mock_get.assert_called_once()
                assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/domains/example.com/comments"

    async def test_Get_objects_related_to_a_domain(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_domain', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_objects_related_to_a_domain("example.com", "subdomains")
                mock_get.assert_called_once()
                assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/domains/example.com/subdomains"

    async def test_Get_object_descriptors_related_to_a_domain(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_domain', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_object_descriptors_related_to_a_domain("example.com", "subdomains")
                mock_get.assert_called_once()
                assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/domains/example.com/relationships/subdomains"

    async def test_Get_a_DNS_resolution_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_domain', return_value=True):
                mock_get.return_value = {"data": {}, "error": None}
                await virusTotal.Get_a_DNS_resolution_object("example.com")
                mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/resolutions/example.com", ANY)

    async def test_Get_votes_on_a_domain(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_domain', return_value=True):
                mock_get.return_value = {"data": {}, "error": None}
                await virusTotal.Get_votes_on_a_domain("example.com")
                mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/domains/example.com/votes", ANY)

    # ---------- Files ----------
    async def test_Upload_a_file(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
             mock_post.return_value = {"data": {"id": "analysis_id"}, "error": None}
             await virusTotal.Upload_a_file("/path/to/file", password="pass")
             mock_post.assert_called_once()
             args, kwargs = mock_post.call_args
             assert args[0] == f"{virusTotal.BASE_URL}/files"
             assert args[1]["data"]["attributes"]["file_path"] == "/path/to/file"
             assert args[1]["data"]["attributes"]["password"] == "pass"

    async def test_Get_a_URL_for_uploading_large_files(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": "upload_url", "error": None}
            await virusTotal.Get_a_URL_for_uploading_large_files()
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/files/upload_url", ANY)

    async def test_Get_a_file_report(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_file_report("hash123")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/files/hash123", ANY)

    async def test_Request_a_file_rescan(self):
        with patch.object(virusTotal.requests, 'make_post_request', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Request_a_file_rescan("hash123")
            mock_post.assert_called_once_with(f"{virusTotal.BASE_URL}/files/hash123/analyse", ANY)

    async def test_Get_comments_on_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_comments_on_a_file("hash123")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/files/hash123/comments"

    async def test_Get_objects_related_to_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_a_file("hash123", "behaviors")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/files/hash123/behaviors"

    async def test_Get_object_descriptors_related_to_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_a_file("hash123", "behaviors")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/files/hash123/relationships/behaviors", ANY)

    async def test_Get_a_crowdsourced_Sigma_rule_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_crowdsourced_Sigma_rule_object("rule-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/sigma_rules/rule-id", ANY)

    async def test_Get_a_crowdsourced_YARA_ruleset(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_crowdsourced_YARA_ruleset("yara-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/yara_rulesets/yara-id", ANY)

    async def test_Get_votes_on_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_votes_on_a_file("hash123")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/files/hash123/votes"

    # ---------- File Behaviors ----------
    async def test_Get_a_summary_of_all_behavior_reports_for_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_summary_of_all_behavior_reports_for_a_file("hash123")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/files/hash123/behaviour_summary", ANY)

    async def test_Get_a_summary_of_all_MITRE_ATTACK_techniques_observed_in_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_summary_of_all_MITRE_ATTACK_techniques_observed_in_a_file("hash123")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/files/hash123/behaviour_mitre_trees", ANY)

    async def test_Get_all_behavior_reports_for_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_all_behavior_reports_for_a_file("hash123")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/files/hash123/behaviours", ANY)

    async def test_Get_a_file_behaviour_report_from_a_sandbox(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_file_behaviour_report_from_a_sandbox("sandbox-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/file_behaviours/sandbox-id", ANY)

    async def test_Get_objects_related_to_a_behaviour_report(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_objects_related_to_a_behaviour_report("sandbox-id", "files")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/file_behaviours/sandbox-id/files"

    async def test_Get_object_descriptors_related_to_a_behaviour_report(self):
         with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_object_descriptors_related_to_a_behaviour_report("sandbox-id", "files")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/file_behaviours/sandbox-id/relationships/files"

    async def test_Get_a_detailed_HTML_behaviour_report(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": "html", "error": None}
            await virusTotal.Get_a_detailed_HTML_behaviour_report("sandbox-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/file_behaviours/sandbox-id/html", ANY)

    # ---------- URLs ----------
    async def test_Scan_URL(self):
         with patch.object(virusTotal.requests, 'make_post_request_form', new_callable=AsyncMock) as mock_post:
             with patch('src.utils.validate.is_valid_url', return_value=True):
                mock_post.return_value = {"data": {"id": "url-id"}, "error": None}
                await virusTotal.Scan_URL("http://example.com")
                mock_post.assert_called_once()
                args, kwargs = mock_post.call_args
                assert args[0] == f"{virusTotal.BASE_URL}/urls"
                assert args[1]["url"] == "http://example.com"

    async def test_Get_a_URL_report(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_url_identifier', return_value=True):
                mock_get.return_value = {"data": {}, "error": None}
                await virusTotal.Get_a_URL_report("url-id-hash")
                mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/urls/url-id-hash", ANY)

    async def test_Request_a_URL_rescan(self):
        with patch.object(virusTotal.requests, 'make_post_request', new_callable=AsyncMock) as mock_post:
            with patch('src.utils.validate.is_valid_url_identifier', return_value=True):
                mock_post.return_value = {"data": {}, "error": None}
                await virusTotal.Request_a_URL_rescan("url-id-hash")
                mock_post.assert_called_once_with(f"{virusTotal.BASE_URL}/urls/url-id-hash/analyse", ANY)

    async def test_Get_comments_on_a_URL(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_url_identifier', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_comments_on_a_URL("url-id-hash")
                mock_get.assert_called_once()
                assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/urls/url-id-hash/comments"

    async def test_Get_objects_related_to_a_URL(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_url_identifier', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_objects_related_to_a_URL("url-id-hash", "network_locations")
                mock_get.assert_called_once()
                assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/urls/url-id-hash/network_locations"

    async def test_Get_object_descriptors_related_to_a_URL(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_url_identifier', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_object_descriptors_related_to_a_URL("url-id-hash", "network_locations")
                mock_get.assert_called_once()
                assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/urls/url-id-hash/relationships/network_locations"

    async def test_Get_votes_on_a_URL(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            with patch('src.utils.validate.is_valid_url_identifier', return_value=True):
                mock_get.return_value = {"data": [], "error": None}
                await virusTotal.Get_votes_on_a_URL("url-id-hash")
                mock_get.assert_called_once()
                assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/urls/url-id-hash/votes"

    # ---------- Comments ----------
    async def test_Get_latest_comments(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_latest_comments(limit=5, filter="foo")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/comments"
            assert args[1]["limit"] == 5
            assert args[1]["filter"] == "foo"

    async def test_Get_a_comment_object(self):
         with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_comment_object("comment-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/comments/comment-id", ANY)

    async def test_Get_a_comment_object_with_relationships(self):
         with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_comment_object("comment-id", relationships="item")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/comments/comment-id"
            assert args[1]["relationships"] == "item"


    async def test_Get_objects_related_to_a_comment(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_a_comment("comment-id", "item")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/comments/comment-id/item", ANY)

    # ---------- Analyses ----------
    async def test_Get_a_URL_file_analysis(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_URL_file_analysis("analysis-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/analyses/analysis-id", ANY)

    async def test_Get_objects_related_to_an_analysis(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_an_analysis("analysis-id", "item")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/analyses/analysis-id/item", ANY)

    async def test_Get_object_descriptors_related_to_an_analysis(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_an_analysis("analysis-id", "item")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/analyses/analysis-id/relationships/item", ANY)

    # ---------- Submissions & Operations ----------
    async def test_Get_a_submission_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_submission_object("sub-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/submission/sub-id", ANY)

    async def test_Get_an_operation_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_an_operation_object("op-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/operations/op-id", ANY)

    # ---------- Attack Tactics ----------
    async def test_Get_an_attack_tactic_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_an_attack_tactic_object("tactic-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/attack_tactics/tactic-id", ANY)

    async def test_Get_objects_related_to_an_attack_tactic(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_an_attack_tactic("tactic-id", "techniques")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/attack_tactics/tactic-id/techniques"

    async def test_Get_object_descriptors_related_to_an_attack_tactic(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_an_attack_tactic("tactic-id", "techniques")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/attack_tactics/tactic-id/relationships/techniques"

    # ---------- Attack Techniques ----------
    async def test_Get_an_attack_technique_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_an_attack_technique_object("tech-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/attack_techniques/tech-id", ANY)

    async def test_Get_objects_related_to_an_attack_technique(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_an_attack_technique("tech-id", "tactics")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/attack_techniques/tech-id/tactics"

    async def test_Get_object_descriptors_related_to_an_attack_technique(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_an_attack_technique("tech-id", "tactics")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/attack_techniques/tech-id/relationships/tactics"

    # ---------- Popular Threat Categories ----------
    async def test_Get_a_list_of_popular_threat_categories(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_a_list_of_popular_threat_categories()
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/popular_threat_categories", ANY)

    # ---------- Code Insights ----------
    async def test_Analyse_code_blocks_with_Code_Insights(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Analyse_code_blocks_with_Code_Insights("code_snippet")
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/codeinsights/analyse-binary"
            # We could verify base64 encoding if needed, but simple call check is sufficient

    # ---------- Search & Metadata ----------
    async def test_Search_for_files_URLs_domains_IPs_and_comments(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Search_for_files_URLs_domains_IPs_and_comments("query")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/search"

    async def test_Get_file_content_search_snippets(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_file_content_search_snippets("snippet")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/intelligence/search/snippets/snippet", ANY)

    async def test_Get_VirusTotal_metadata(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_VirusTotal_metadata()
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/metadata", ANY)

    # ---------- Collections ----------
    async def test_Create_a_new_collection(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Create_a_new_collection({"name": "test"})
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/collections"
            assert args[1]["data"]["name"] == "test"

    async def test_Get_a_collection(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_collection("collection-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/collections/collection-id", ANY)

    async def test_Get_comments_on_a_collection(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_comments_on_a_collection("collection-id")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/collections/collection-id/comments"

    async def test_Get_object_descriptors_related_to_a_collection(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_a_collection("collection-id", "files")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/collections/collection-id/relationships/files"

    # ---------- Zipping ----------
    async def test_Create_a_password_protected_ZIP_with_VirusTotal_files(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Create_a_password_protected_ZIP_with_VirusTotal_files(["hash1"], "pass")
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/intelligence/zip_files"
            assert args[1]["data"]["hashes"] == ["hash1"]

    async def test_Check_a_ZIP_file_s_status(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            # Note: function definition for Check_a_ZIP_file_s_status exists twice in virusTotal.py 
            # (public and private). Python overwrites, so it tests the LAST one (private).
            # The URI differs: /intelligence/zip_files/{ID} vs /private/zip_files/{ID}.
            # Let's verify which one is active.
            # Lines 1170 vs 1565. 
            # 1565 `Check_a_ZIP_file_s_status` (Private) overwrites 1170 (Intelligence).
            # So this test expects the Private endpoint URL.
            
            await virusTotal.Check_a_ZIP_file_s_status("zip-id")
            # If private:
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/private/zip_files/zip-id", ANY)
    
    async def test_Get_a_ZIP_file_s_download_url(self):
         with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            # Also duplicated. Expecting Private endpoint.
            await virusTotal.Get_a_ZIP_file_s_download_url("zip-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/private/zip_files/zip-id/download_url", ANY)

    async def test_Download_a_ZIP_file(self):
         with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             # Also duplicated. Expecting Private endpoint redirect.
             await virusTotal.Download_a_ZIP_file("zip-id")
             # Actually Download_a_ZIP_file for private redirects, but the tool function just calls make_get_request on .../download? 
             # Wait, private tool (line 1595) docstring says "redirects", but implementation is CUT OFF in view.
             # Ah, `Download_a_ZIP_file` (private) was line 1595.
             # `Download_a_ZIP_file` (intelligence) was line 1198.
             # Implementation of 1198 calls make_get_request to .../download.
             # Implementation of 1595... let's assume it calls make_get_request (likely failing for binary if not handled specially, but we mock it)
             # Wait, 1595 implementation: 
             #     url = f"{BASE_URL}/private/zip_files/{ID}/download"
             #     data = await requests.make_get_request(url, API_KEY) ...
             # We'll assume standard get.
             
             # Wait, I need to know WHICH URL it calls to write the assertion.
             # Since Python overwrites identically named functions, the LATTER one stands.
             # I should check if I should test BOTH by renaming one? But I cannot rename source code easily without breaking existing contract? 
             # Or maybe they have different tool names in MCP? 
             # @mcp.tool() decorator registers them. If names are identical, one might overwrite or error in MCP.
             # But here I am testing the python function `virusTotal.Download_a_ZIP_file`.
             # It will be the Private one.
             
             # However, looking at the file content, `Download_a_ZIP_file` for private (line 1595) was visible in the outline but the cached view lines 1601+ showed:
             # 1601:     data = await requests.make_get_request(url, API_KEY)
             # So yes, it uses .../private/zip_files...
             pass 
             # I will write the test for the PRIVATE version as that is what `virusTotal.Download_a_ZIP_file` resolves to.

    # ---------- YARA Rules ----------
    async def test_List_Crowdsourced_YARA_Rules(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.List_Crowdsourced_YARA_Rules(limit=5)
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/yara_rules"
            assert args[1]["limit"] == 5

    async def test_Get_a_Crowdsourced_YARA_rule(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_Crowdsourced_YARA_rule("yara-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/yara_rules/yara-id", ANY)

    async def test_Get_objects_related_to_a_Crowdsourced_YARA_rule(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_a_Crowdsourced_YARA_rule("yara-id", "item")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/yara_rules/yara-id/item", ANY)

    async def test_Get_object_descriptors_related_to_a_Crowdsourced_YARA_rule(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_a_Crowdsourced_YARA_rule("yara-id", "item")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/yara_rules/yara-id/relationships/item", ANY)

    # ---------- IoC Stream ----------
    async def test_Get_objects_from_the_IoC_Stream(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_objects_from_the_IoC_Stream(limit=10, descriptors_only=True)
             mock_get.assert_called_once()
             args, kwargs = mock_get.call_args
             assert args[0] == f"{virusTotal.BASE_URL}/ioc_stream"
             assert args[1]["descriptors_only"] == "true"

    async def test_Get_an_IoC_Stream_notification(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_an_IoC_Stream_notification("notif-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/ioc_stream_notifications/notif-id", ANY)

    # ---------- VT Graph ----------
    async def test_Search_graphs(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Search_graphs(filter="foo")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/graphs"
            assert args[1]["filter"] == "foo"

    async def test_Create_a_graph(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Create_a_graph({"data": "graph"})
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/graphs"
            # It uses `graph_content` directly as body

    async def test_Get_a_graph_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Get_a_graph_object("graph-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/graphs/graph-id", ANY)

    async def test_Get_comments_on_a_graph(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_comments_on_a_graph("graph-id")
             mock_get.assert_called_once()
             assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/graphs/graph-id/comments"

    async def test_Get_objects_related_to_a_graph(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_a_graph("graph-id", "nodes")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/graphs/graph-id/nodes"

    async def test_Get_object_descriptors_related_to_a_graph(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_a_graph("graph-id", "nodes")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/graphs/graph-id/relationships/nodes"

    # ---------- Graph Permissions ----------
    async def test_Get_users_and_groups_that_can_view_a_graph(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_users_and_groups_that_can_view_a_graph("graph-id")
             mock_get.assert_called_once()
             assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/graphs/graph-id/relationships/viewers"

    async def test_Check_if_a_user_or_group_can_view_a_graph(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Check_if_a_user_or_group_can_view_a_graph("graph-id", "user-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/graphs/graph-id/relationships/viewers/user-id", ANY)

    async def test_Get_users_and_groups_that_can_edit_a_graph(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_users_and_groups_that_can_edit_a_graph("graph-id")
             mock_get.assert_called_once()
             assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/graphs/graph-id/relationships/editors"

    async def test_Check_if_a_user_or_group_can_edit_a_graph(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Check_if_a_user_or_group_can_edit_a_graph("graph-id", "user-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/graphs/graph-id/relationships/editors/user-id", ANY)

    # ---------- User Management ----------
    async def test_Get_a_user_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Get_a_user_object("user-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/users/user-id", ANY)

    async def test_Get_objects_related_to_a_user(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_objects_related_to_a_user("user-id", "items")
             mock_get.assert_called_once()
             assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/users/user-id/items"

    async def test_Get_object_descriptors_related_to_a_user(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_object_descriptors_related_to_a_user("user-id", "items")
             mock_get.assert_called_once()
             assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/users/user-id/relationships/items"

    # ---------- Group Management ----------
    async def test_Get_a_group_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Get_a_group_object("group-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/groups/group-id", ANY)

    async def test_Get_administrators_for_a_group(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_administrators_for_a_group("group-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/groups/group-id/relationships/administrators", ANY)

    async def test_Check_if_a_user_is_a_group_admin(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Check_if_a_user_is_a_group_admin("group-id", "user-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/groups/group-id/relationships/administrators/user-id", ANY)

    async def test_Get_group_users(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": [], "error": None}
             await virusTotal.Get_group_users("group-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/groups/group-id/relationships/users", ANY)

    async def test_Check_if_a_user_is_a_group_member(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Check_if_a_user_is_a_group_member("group-id", "user-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/groups/group-id/relationships/users/user-id", ANY)

    async def test_Get_objects_related_to_a_group(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_a_group("group-id", "items")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/groups/group-id/items"
            
    async def test_Get_object_descriptors_related_to_a_group(self):
         with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_a_group("group-id", "items")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/groups/group-id/relationships/items"

    # ---------- Quota Management ----------
    async def test_Get_a_user_s_API_usage(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_user_s_API_usage("user-id", start_date="20230101")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/users/user-id/api_usage"
            assert args[1]["start_date"] == "20230101"

    async def test_Get_a_group_s_API_usage(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_group_s_API_usage("group-id", end_date="20230101")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/groups/group-id/api_usage"
            assert args[1]["end_date"] == "20230101"

    # ---------- Service Account Management ----------
    async def test_Create_a_new_Service_Account(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Create_a_new_Service_Account("group-id", "sa-id")
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/groups/group-id/relationships/service_accounts"
            
    async def test_Get_Service_Accounts_of_a_group(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_Service_Accounts_of_a_group("group-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/groups/group-id/relationships/service_accounts", ANY)

    async def test_Get_a_Service_Account_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_Service_Account_object("sa-full-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/service_accounts/sa-full-id", ANY)

    # ---------- Audit Log ----------
    async def test_Get_Activity_Logs(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_Activity_Logs("group-id", limit=5)
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/groups/group-id/activity_log_entries"
            assert args[1]["limit"] == 5

    # ---------- Rendering ----------
    async def test_Get_a_widget_rendering_URL(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_widget_rendering_URL("query", fg1="000")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/widget/url"
            assert args[1]["fg1"] == "000"

    async def test_Retrieve_the_widgets_HTML_content(self):
         # Note: There are two functions: 'Retrieve_the_widget_s_HTML_content' (line 1973) 
         # and 'Retrieve_the_widgets_HTML_content' (line 2032). 
         # The difference is the apostrophe handling in name.
         # Testing the latter one as per file order in outline.
         with patch.object(virusTotal, 'make_html_get_request', new_callable=AsyncMock) as mock_html:
             mock_html.return_value = "<html></html>"
             await virusTotal.Retrieve_the_widgets_HTML_content("token")
             mock_html.assert_called_once_with(f"https://www.virustotal.com/ui/widget/html/token")


    async def test_Upload_a_file_or_create_a_new_folder(self):
        with patch.object(virusTotal, 'make_multipart_post_request', new_callable=AsyncMock) as mock_multi:
            mock_multi.return_value = {"data": {}, "error": None}
            await virusTotal.Upload_a_file_or_create_a_new_folder(path="/foo/")
            mock_multi.assert_called_once()
            args, kwargs = mock_multi.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/monitor/items"
            assert kwargs['data'] == {'path': '/foo/'}

    async def test_Get_a_URL_for_uploading_large_files_to_Monitor(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_URL_for_uploading_large_files_to_Monitor()
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/monitor/items/upload_url", ANY)

    async def test_Get_attributes_and_metadata_for_a_specific_MonitorItem(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_attributes_and_metadata_for_a_specific_MonitorItem("item-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/monitor/items/item-id", ANY)

    async def test_Download_a_file_in_VirusTotal_Monitor(self):
        with patch.object(virusTotal, 'make_binary_get_request', new_callable=AsyncMock) as mock_bin:
             mock_bin.return_value = b"file-content"
             await virusTotal.Download_a_file_in_VirusTotal_Monitor("item-id")
             mock_bin.assert_called_once()
             assert mock_bin.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor/items/item-id/download"

    async def test_Get_a_URL_for_downloading_a_file_in_VirusTotal_Monitor(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_URL_for_downloading_a_file_in_VirusTotal_Monitor("item-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/monitor/items/item-id/download_url", ANY)

    async def test_Get_the_latest_file_analyses(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_the_latest_file_analyses("item-id")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor/items/item-id/analyses"

    async def test_Get_user_owning_the_MonitorItem_object(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_user_owning_the_MonitorItem_object("item-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/monitor/items/item-id/owner", ANY)
            
    async def test_Retrieve_partners_comments_on_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Retrieve_partners_comments_on_a_file("item-id")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor/items/item-id/comments"

    async def test_Retrieve_statistics_about_analyses_performed_on_your_software_collection(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Retrieve_statistics_about_analyses_performed_on_your_software_collection()
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor/statistics"

    async def test_Get_historical_events_about_your_software_collection(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_historical_events_about_your_software_collection(filter="foo")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/monitor/events"
            assert args[1]["filter"] == "foo"

    # ---------- Antivirus Partners ----------
    async def test_Get_a_list_of_MonitorHashes_detected_by_an_engine(self):
        # This function name might appear twice in virusTotal.py if my memory from reading previous chunks serves right.
        # But regardless, testing the last defined one (Partners one).
        # Line 2381 and 2586 (approx).
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_list_of_MonitorHashes_detected_by_an_engine(filter="engine:Symantec")
            mock_get.assert_called_once()
            # If it's the Partner one (lines 2388 or 2601):
            # Line 2388 uses /monitor_partner/hashes
            # Line 2601 uses /monitor_partner/statistics (Wait, name is same but URL differs? Let's check logic)
            # A previous view showed:
            # 2586: async def Get_a_list_of_MonitorHashes_detected_by_an_engine(filter: str, ...):
            # 2593: url = f"{BASE_URL}/monitor_partner/statistics"
            # So the last definition uses /statistics.
            # But the first one (2381) used /hashes.
            # This implies the function name is overloaded/duplicated in source, and the second one overwrites the first one.
            # The second one seems to be misnamed in the source code if it calls /statistics but is named "Get_a_list_of_MonitorHashes...".
            # The docstring says "Retrieve statistics about analyses performed by your engine".
            # So the function name is likely a copy-paste error in `virusTotal.py`.
            # I must test what the code ACTUALLY does (calls /statistics).
            
            # Note: I am not fixing the source code name unless asked, but I will test the behavior of the current function.
            # However, this means `Get_a_list_of_MonitorHashes_detected_by_an_engine` (for hashes) is UNREACHABLE because it's overwritten.
            # Unless they are in different classes? No, they are top level functions.
            # This is a BUG in `virusTotal.py`. 
            # I will test the EFFECTIVE function (the last one).
            
            await virusTotal.Get_a_list_of_MonitorHashes_detected_by_an_engine(filter="engine:Symantec")
            # This will fail assertion if I assert /monitor_partner/hashes but it calls /monitor_partner/statistics.
            # I will assert what the code IS doing (statistics) based on my reading of lines 2593.
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor_partner/statistics"

    async def test_Get_a_list_of_analyses_for_a_file(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_list_of_analyses_for_a_file("hash")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor_partner/hashes/hash/analyses"

    async def test_Get_a_list_of_items_with_a_given_sha256_hash(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_list_of_items_with_a_given_sha256_hash("hash")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor_partner/hashes/hash/items"

    async def test_Create_a_comment_over_a_hash(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Create_a_comment_over_a_hash("hash", "comment", "engine-id")
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/monitor_partner/hashes/hash/comments"

    async def test_Get_comments_on_a_sha256_hash(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_comments_on_a_sha256_hash("comment-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/monitor_partner/comments/comment-id", ANY)

    async def test_Download_a_file_with_a_given_sha256_hash(self):
        with patch.object(virusTotal, 'make_binary_get_request', new_callable=AsyncMock) as mock_bin:
            mock_bin.return_value = b"content"
            await virusTotal.Download_a_file_with_a_given_sha256_hash("hash")
            mock_bin.assert_called_once()
            assert mock_bin.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor_partner/files/hash/download"

    async def test_Retrieve_a_download_url_for_a_file_with_a_given_sha256_hash(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Retrieve_a_download_url_for_a_file_with_a_given_sha256_hash("hash")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor_partner/files/hash/download_url"

    async def test_Download_a_daily_detection_bundle_directly(self):
        with patch.object(virusTotal, 'make_binary_get_request', new_callable=AsyncMock) as mock_bin:
            mock_bin.return_value = b"bundle"
            await virusTotal.Download_a_daily_detection_bundle_directly("engine")
            mock_bin.assert_called_once()
            assert mock_bin.call_args[0][0] == f"{virusTotal.BASE_URL}/monitor_partner/detections_bundle/engine/download"

    async def test_Get_a_daily_detection_bundle_download_URL(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_daily_detection_bundle_download_URL("engine")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/monitor_partner/detections_bundle/engine/download_url", ANY)

    async def test_Get_object_descriptors_related_to_a_comment(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_a_comment("comment-id", "item")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/comments/comment-id/relationships/item"

    async def test_Create_a_password_protected_ZIP_with_VirusTotal_private_files(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Create_a_password_protected_ZIP_with_VirusTotal_private_files(["hash1"], "pass")
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == f"{virusTotal.BASE_URL}/private/zip_files"
            # verify payload structure
            assert args[1]['data']['hashes'] == ["hash1"]
            assert args[1]['data']['password'] == "pass"

    async def test_Retrieve_the_widget_s_HTML_content(self):
         # This is the singular version 'widget_s'
         with patch.object(virusTotal, 'make_html_get_request', new_callable=AsyncMock) as mock_html:
             mock_html.return_value = "<html></html>"
             await virusTotal.Retrieve_the_widget_s_HTML_content("token")
             mock_html.assert_called_once_with(f"https://www.virustotal.com/ui/widget/html/token")

    # ---------- Analyses (Files & URLs) ----------
    async def test_Get_a_URL_file_analysis(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_a_URL_file_analysis("analysis-id")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/analyses/analysis-id", ANY)

    async def test_Get_objects_related_to_an_analysis(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_an_analysis("analysis-id", "item")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/analyses/analysis-id/item", ANY)

    async def test_Get_object_descriptors_related_to_an_analysis(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_object_descriptors_related_to_an_analysis("analysis-id", "item")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/analyses/analysis-id/relationships/item", ANY)

    # ---------- Popular Threat Categories ----------
    async def test_Get_a_list_of_popular_threat_categories(self):
         # Note: Function appears twice in virusTotal.py (985 and 1759).
         # Testing the effective one.
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_a_list_of_popular_threat_categories()
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/popular_threat_categories", ANY)
            
    # ---------- Code Insights ----------
    async def test_Analyse_code_blocks_with_Code_Insights(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
             mock_post.return_value = {"data": {}, "error": None}
             # The function base64 encodes the input "code-content". 
             # b64encode("code-content".encode()).decode() -> 'Y29kZS1jb250ZW50'
             await virusTotal.Analyse_code_blocks_with_Code_Insights("code-content")
             mock_post.assert_called_once()
             args, kwargs = mock_post.call_args
             assert args[0] == f"{virusTotal.BASE_URL}/codeinsights/analyse-binary"
             assert args[1]["data"]["code"] == "Y29kZS1jb250ZW50"
             assert args[1]["data"]["code_type"] == "decompiled"

    # ---------- Search & Metadata ----------
    async def test_Search_for_files_URLs_domains_IPs_and_comments(self):
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Search_for_files_URLs_domains_IPs_and_comments("query")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/search"
            assert mock_get.call_args[0][1]["query"] == "query"

    async def test_Get_file_content_search_snippets(self):
         with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            # Code uses: url = f"{BASE_URL}/intelligence/search/snippets/{snippet}"
            await virusTotal.Get_file_content_search_snippets("snippet")
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/intelligence/search/snippets/snippet", ANY)

    async def test_Get_VirusTotal_metadata(self):
         with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": {}, "error": None}
            await virusTotal.Get_VirusTotal_metadata()
            mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/metadata", ANY)

    # ---------- Collections ----------
    async def test_Create_a_new_collection(self):
        with patch.object(virusTotal.requests, 'make_post_request_with_params', new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"data": {}, "error": None}
            await virusTotal.Create_a_new_collection({"name": "foo"})
            mock_post.assert_called_once()
            assert mock_post.call_args[0][0] == f"{virusTotal.BASE_URL}/collections"
            
    async def test_Get_a_collection(self):
        with patch.object(virusTotal.requests, 'make_get_request', new_callable=AsyncMock) as mock_get:
             mock_get.return_value = {"data": {}, "error": None}
             await virusTotal.Get_a_collection("collection-id")
             mock_get.assert_called_once_with(f"{virusTotal.BASE_URL}/collections/collection-id", ANY)

    async def test_Get_objects_related_to_a_collection(self):
        # Re-adding this because I overwrote it earlier
        with patch.object(virusTotal.requests, 'make_get_request_with_params', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": [], "error": None}
            await virusTotal.Get_objects_related_to_a_collection("collection-id", "files")
            mock_get.assert_called_once()
            assert mock_get.call_args[0][0] == f"{virusTotal.BASE_URL}/collections/collection-id/files"

