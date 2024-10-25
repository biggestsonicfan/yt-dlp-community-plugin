import base64
import os
import re
import sys
import json
import itertools

from yt_dlp.extractor.youtube import YoutubeTabBaseInfoExtractor, BadgeType
from yt_dlp.networking import HEADRequest
from yt_dlp.utils import (
    ExtractorError,
    traverse_obj,
    try_get,
    str_or_none,
    urlhandle_detect_ext,
    get_first,
    int_or_none,
    urljoin,
    parse_count,
    url_or_none
    )


YoutubeTabBaseInfoExtractor._RESERVED_NAMES = (
    r'channel|c|user|playlist|watch|w|v|embed|e|live|watch_popup|clip|'
    r'shorts|movies|results|search|shared|hashtag|trending|explore|feed|feeds|'
    r'browse|oembed|get_video_info|iframe_api|s/player|source|'
    r'storefront|oops|index|account|t/terms|about|upload|signin|logout|post')


class YoutubePostIE(YoutubeTabBaseInfoExtractor):
    IE_DESC = 'YouTube Community Posts'
    IE_NAME = 'youtube:post'
    _VALID_URL = r'https?://(?:www\.)?youtube\.com/post/(?P<id>[^/#?]+)'

    def _real_extract(self, url):
        post_id = self._match_id(url)
        webpage = self._download_webpage(url, post_id)
        initial_data = self.extract_yt_initial_data(post_id, webpage)
        self._dump_json(initial_data, "initial_data")
        self.report_warning(f"{os.getcwd()}")
        ytcfg = self.extract_ytcfg(post_id, webpage)
        backstage_post_renderer = traverse_obj(initial_data, (
            'contents', 'twoColumnBrowseResultsRenderer', 'tabs', 0, 'tabRenderer', 'content',
            'sectionListRenderer', 'contents', 0, 'itemSectionRenderer', 'contents', 0,
            'backstagePostThreadRenderer', 'post', 'backstagePostRenderer', {dict})) or {}
        author_text = traverse_obj(backstage_post_renderer, (
            'authorText', 'runs', ..., {dict}), get_all=False) or {}
        channel = author_text.get('text')
        # TODO: Can't handle multiple images in one
        backstage_attachment = traverse_obj(backstage_post_renderer, ('backstageAttachment'), {dict})
        image_attchment = traverse_obj(backstage_attachment, ('backstageImageRenderer'), {dict})
        image_attchments = traverse_obj(backstage_attachment, ('postMultiImageRenderer', 'images', ..., 'backstageImageRenderer'), {dict})
        formats = self._extract_thumbnails(image_attchment, ('image'))
        if not formats:
            formats = self._extract_thumbnails(image_attchments, (..., 'image'))
        tracking_param = traverse_obj(formats, ('trackingParams'))
        width = max(traverse_obj(formats, (..., 'width')) or [0]) or None
        height = max(traverse_obj(formats, (..., 'height')) or [0]) or None
        transcode_url = traverse_obj(formats, (..., 'url'), get_all=False) or ''
        original_url = re.sub(r'=s\d+(?:[\w-]+)?(?:=[^=]+)*$', '=s0?imgmax=0', transcode_url)
        if original_url and original_url != transcode_url:
            formats.append({'url': original_url, 'width': width, 'height': height, 'format_id': 'original'})
        ext = 'jpg'
        for fmt in reversed(formats):
            urlh = self._request_webpage(
                HEADRequest(fmt['url']), post_id, 'Requesting image information', fatal=False)
            if not urlh:
                continue
            ext = urlhandle_detect_ext(urlh, default='jpg')
            break
        for fmt in formats:
            if not fmt.get('format_id') and fmt.get('height'):
                fmt['format_id'] = str(fmt['height'])
            fmt['ext'] = ext

        return {
            **traverse_obj(author_text, ('navigationEndpoint', 'browseEndpoint', {
                'channel_id': ('browseId', {str}),
                'uploader_id': ('canonicalBaseUrl', {self.handle_from_url}),
            })),
            'timestamp': self._parse_time_text(self._get_text(backstage_post_renderer, 'publishedTimeText')),
            'channel': channel,
            'uploader': channel,
            'id': post_id,
            'title': self._get_text(backstage_post_renderer, 'contentText'),
            'formats': formats,
            'tracking_parm': tracking_param,
            '__post_extractor': self.extract_comments(ytcfg, post_id, initial_data)
        }
    
    def _extract_comment(self, entities, parent=None):
        comment_entity_payload = get_first(entities, ('payload', 'commentEntityPayload', {dict}))
        if not (comment_id := traverse_obj(comment_entity_payload, ('properties', 'commentId', {str}))):
            return

        toolbar_entity_payload = get_first(entities, ('payload', 'engagementToolbarStateEntityPayload', {dict}))
        time_text = traverse_obj(comment_entity_payload, ('properties', 'publishedTime', {str})) or ''

        return {
            'id': comment_id,
            'parent': parent or 'root',
            **traverse_obj(comment_entity_payload, {
                'text': ('properties', 'content', 'content', {str}),
                'like_count': ('toolbar', 'likeCountA11y', {parse_count}),
                'author_id': ('author', 'channelId', {self.ucid_or_none}),
                'author': ('author', 'displayName', {str}),
                'author_thumbnail': ('author', 'avatarThumbnailUrl', {url_or_none}),
                'author_is_uploader': ('author', 'isCreator', {bool}),
                'author_is_verified': ('author', 'isVerified', {bool}),
                'author_is_member': ('author', 'sponsorBadgeA11y', {str}),
                'author_member_badge': ('author', 'sponsorBadgeUrl', {url_or_none}),
                'author_url': ('author', 'channelCommand', 'innertubeCommand', (
                    ('browseEndpoint', 'canonicalBaseUrl'), ('commandMetadata', 'webCommandMetadata', 'url'),
                ), {lambda x: urljoin('https://www.youtube.com', x)}),
            }, get_all=False),
            'is_favorited': (None if toolbar_entity_payload is None else
                             toolbar_entity_payload.get('heartState') == 'TOOLBAR_HEART_STATE_HEARTED'),
            '_time_text': time_text,  # FIXME: non-standard, but we need a way of showing that it is an estimate.
            'timestamp': self._parse_time_text(time_text),
        }

    def _extract_comment_old(self, comment_renderer, parent=None):
        comment_id = comment_renderer.get('commentId')
        if not comment_id:
            return

        info = {
            'id': comment_id,
            'text': self._get_text(comment_renderer, 'contentText'),
            'like_count': self._get_count(comment_renderer, 'voteCount'),
            'author_id': traverse_obj(comment_renderer, ('authorEndpoint', 'browseEndpoint', 'browseId', {self.ucid_or_none})),
            'author': self._get_text(comment_renderer, 'authorText'),
            'author_thumbnail': traverse_obj(comment_renderer, ('authorThumbnail', 'thumbnails', -1, 'url', {url_or_none})),
            'parent': parent or 'root',
        }

        # Timestamp is an estimate calculated from the current time and time_text
        time_text = self._get_text(comment_renderer, 'publishedTimeText') or ''
        timestamp = self._parse_time_text(time_text)

        info.update({
            # FIXME: non-standard, but we need a way of showing that it is an estimate.
            '_time_text': time_text,
            'timestamp': timestamp,
        })

        info['author_url'] = urljoin(
            'https://www.youtube.com', traverse_obj(comment_renderer, ('authorEndpoint', (
                ('browseEndpoint', 'canonicalBaseUrl'), ('commandMetadata', 'webCommandMetadata', 'url'))),
                expected_type=str, get_all=False))

        author_is_uploader = traverse_obj(comment_renderer, 'authorIsChannelOwner')
        if author_is_uploader is not None:
            info['author_is_uploader'] = author_is_uploader

        comment_abr = traverse_obj(
            comment_renderer, ('actionButtons', 'commentActionButtonsRenderer'), expected_type=dict)
        if comment_abr is not None:
            info['is_favorited'] = 'creatorHeart' in comment_abr

        badges = self._extract_badges([traverse_obj(comment_renderer, 'authorCommentBadge')])
        if self._has_badge(badges, BadgeType.VERIFIED):
            info['author_is_verified'] = True

        is_pinned = traverse_obj(comment_renderer, 'pinnedCommentBadge')
        if is_pinned:
            info['is_pinned'] = True

        return info
    
    def _comment_entries(self, root_continuation_data, ytcfg, video_id, parent=None, tracker=None):
        get_single_config_arg = lambda c: self._configuration_arg(c, [''])[0]

        #Backup
        '''
                def extract_header(contents):
            _continuation = None
            for content in contents:
                comments_header_renderer = traverse_obj(content, 'onResponseReceivedEndpoints', 0,
                    'reloadContinuationItemsCommand', 'continuationItems', ..., 'commentsHeaderRenderer')
                expected_comment_count = self._get_count(
                    comments_header_renderer, 'countText', 'commentsCount')

                if expected_comment_count is not None:
                    tracker['est_total'] = expected_comment_count
                    self.to_screen(f'Downloading ~{expected_comment_count} comments')
                comment_sort_index = int(get_single_config_arg('comment_sort') != 'top')  # 1 = new, 0 = top
                self._dump_json(comments_header_renderer, "comments_header_renderer")
                sort_menu_item = try_get(
                    comments_header_renderer,
                    lambda x: x['sortMenu']['sortFilterSubMenuRenderer']['subMenuItems'][comment_sort_index], dict) or {}
                sort_continuation_ep = sort_menu_item.get('serviceEndpoint') or {}

                _continuation = self._extract_continuation_ep_data(sort_continuation_ep) or self._extract_continuation(sort_menu_item)
                if not _continuation:
                    continue

                sort_text = str_or_none(sort_menu_item.get('title'))
                if not sort_text:
                    sort_text = 'top comments' if comment_sort_index == 0 else 'newest first'
                self.to_screen(f'Sorting comments by {sort_text.lower()}')
                break
            return _continuation
        '''
        def extract_header(contents):
            _continuation = None
            for content in contents:
                comments_header_renderer = traverse_obj(content, 'onResponseReceivedEndpoints', 0,
                    'reloadContinuationItemsCommand', 'continuationItems', ..., 'commentsHeaderRenderer')
                
                expected_comment_count = int(comments_header_renderer[0]['countText']['runs'][0]['text'])

                if expected_comment_count is not None:
                    tracker['est_total'] = expected_comment_count
                    self.to_screen(f'Downloading ~{expected_comment_count} comments')
                comment_sort_index = int(get_single_config_arg('comment_sort') != 'top')  # 1 = new, 0 = top
                self._dump_json(comments_header_renderer, "comments_header_renderer")
                sort_menu_item = try_get(
                    comments_header_renderer[0],
                    lambda x: x['sortMenu']['sortFilterSubMenuRenderer']['subMenuItems'][comment_sort_index], dict) or {}
                sort_continuation_ep = sort_menu_item.get('serviceEndpoint') or {}

                _continuation = self._extract_continuation_ep_data(sort_continuation_ep) or self._extract_continuation(sort_menu_item)
                if not _continuation:
                    continue

                sort_text = str_or_none(sort_menu_item.get('title'))
                if not sort_text:
                    sort_text = 'top comments' if comment_sort_index == 0 else 'newest first'
                self.to_screen(f'Sorting comments by {sort_text.lower()}')
                break
            return _continuation

        def extract_thread(contents, entity_payloads):
            if not parent:
                tracker['current_page_thread'] = 0
            for content in contents:
                if not parent and tracker['total_parent_comments'] >= max_parents:
                    yield
                comment_thread_renderer = try_get(content, lambda x: x['commentThreadRenderer'])

                # old comment format
                if not entity_payloads:
                    comment_renderer = get_first(
                        (comment_thread_renderer, content), [['commentRenderer', ('comment', 'commentRenderer')]],
                        expected_type=dict, default={})

                    comment = self._extract_comment_old(comment_renderer, parent)

                # new comment format
                else:
                    view_model = (
                        traverse_obj(comment_thread_renderer, ('commentViewModel', 'commentViewModel', {dict}))
                        or traverse_obj(content, ('commentViewModel', {dict})))
                    comment_keys = traverse_obj(view_model, (('commentKey', 'toolbarStateKey'), {str}))
                    if not comment_keys:
                        continue
                    entities = traverse_obj(entity_payloads, lambda _, v: v['entityKey'] in comment_keys)
                    comment = self._extract_comment(entities, parent)
                    if comment:
                        comment['is_pinned'] = traverse_obj(view_model, ('pinnedText', {str})) is not None

                if not comment:
                    continue
                comment_id = comment['id']

                if comment.get('is_pinned'):
                    tracker['pinned_comment_ids'].add(comment_id)
                # Sometimes YouTube may break and give us infinite looping comments.
                # See: https://github.com/yt-dlp/yt-dlp/issues/6290
                if comment_id in tracker['seen_comment_ids']:
                    if comment_id in tracker['pinned_comment_ids'] and not comment.get('is_pinned'):
                        # Pinned comments may appear a second time in newest first sort
                        # See: https://github.com/yt-dlp/yt-dlp/issues/6712
                        continue
                    self.report_warning(
                        'Detected YouTube comments looping. Stopping comment extraction '
                        f'{"for this thread" if parent else ""} as we probably cannot get any more.')
                    yield
                else:
                    tracker['seen_comment_ids'].add(comment['id'])

                tracker['running_total'] += 1
                tracker['total_reply_comments' if parent else 'total_parent_comments'] += 1
                yield comment

                # Attempt to get the replies
                comment_replies_renderer = try_get(
                    comment_thread_renderer, lambda x: x['replies']['commentRepliesRenderer'], dict)

                if comment_replies_renderer:
                    tracker['current_page_thread'] += 1
                    comment_entries_iter = self._comment_entries(
                        comment_replies_renderer, ytcfg, video_id,
                        parent=comment.get('id'), tracker=tracker)
                    yield from itertools.islice(comment_entries_iter, min(
                        max_replies_per_thread, max(0, max_replies - tracker['total_reply_comments'])))

        # Keeps track of counts across recursive calls
        if not tracker:
            tracker = {
                'running_total': 0,
                'est_total': None,
                'current_page_thread': 0,
                'total_parent_comments': 0,
                'total_reply_comments': 0,
                'seen_comment_ids': set(),
                'pinned_comment_ids': set(),
            }

        # TODO: Deprecated
        # YouTube comments have a max depth of 2
        max_depth = int_or_none(get_single_config_arg('max_comment_depth'))
        if max_depth:
            self._downloader.deprecated_feature('[youtube] max_comment_depth extractor argument is deprecated. '
                                                'Set max replies in the max-comments extractor argument instead')
        if max_depth == 1 and parent:
            return

        max_comments, max_parents, max_replies, max_replies_per_thread, *_ = (
            int_or_none(p, default=sys.maxsize) for p in self._configuration_arg('max_comments') + [''] * 4)
        continuation = self._extract_continuation(root_continuation_data)

        response = None
        is_forced_continuation = False
        is_first_continuation = parent is None
        if is_first_continuation and not continuation:
            # Sometimes you can get comments by generating the continuation yourself,
            # even if YouTube initially reports them being disabled - e.g. stories comments.
            # Note: if the comment section is actually disabled, YouTube may return a response with
            # required check_get_keys missing. So we will disable that check initially in this case.
            continuation = self._build_api_continuation_query(self._generate_comment_continuation(video_id))
            is_forced_continuation = True

        continuation_items_path = (
            'onResponseReceivedEndpoints', ..., 'reloadContinuationItemsCommand', 'continuationItems')
        for page_num in itertools.count(0):
            if not continuation:
                break
            headers = self.generate_api_headers(ytcfg=ytcfg, visitor_data=self._extract_visitor_data(response))
            comment_prog_str = f"({tracker['running_total']}/~{tracker['est_total']})"
            if page_num == 0:
                if is_first_continuation:
                    note_prefix = 'Downloading comment section API JSON'
                else:
                    note_prefix = '    Downloading comment API JSON reply thread %d %s' % (
                        tracker['current_page_thread'], comment_prog_str)
            else:
                note_prefix = '{}Downloading comment{} API JSON page {} {}'.format(
                    '       ' if parent else '', ' replies' if parent else '',
                    page_num, comment_prog_str)

            # Do a deep check for incomplete data as sometimes YouTube may return no comments for a continuation
            # Ignore check if YouTube says the comment count is 0.
            check_get_keys = None
            if not is_forced_continuation and not (tracker['est_total'] == 0 and tracker['running_total'] == 0):
                check_get_keys = [[*continuation_items_path, ..., (
                    'commentsHeaderRenderer' if is_first_continuation else ('commentThreadRenderer', 'commentViewModel', 'commentRenderer'))]]
            try:
                response = self._call_api('browse', continuation, video_id, True, headers, 'Downloading comment section API JSON', 'Oopsies')               
                self._dump_json(response, "new_response")
            except ExtractorError as e:
                # Ignore incomplete data error for replies if retries didn't work.
                # This is to allow any other parent comments and comment threads to be downloaded.
                # See: https://github.com/yt-dlp/yt-dlp/issues/4669
                if 'incomplete data' in str(e).lower() and parent:
                    if self.get_param('ignoreerrors') in (True, 'only_download'):
                        self.report_warning(
                            'Received incomplete data for a comment reply thread and retrying did not help. '
                            'Ignoring to let other comments be downloaded. Pass --no-ignore-errors to not ignore.')
                        return
                    else:
                        raise ExtractorError(
                            'Incomplete data received for comment reply thread. '
                            'Pass --ignore-errors to ignore and allow rest of comments to download.',
                            expected=True)
                raise
            is_forced_continuation = False
            continuation = None
            self._dump_json(response, "continuation_response")
            mutations = traverse_obj(response, ('frameworkUpdates', 'entityBatchUpdate', 'mutations', ..., {dict}))
            for continuation_items in traverse_obj(response, continuation_items_path, expected_type=list, default=[]):
                if is_first_continuation:
                    continuation = extract_header(continuation_items)
                    is_first_continuation = False
                    if continuation:
                        break
                    continue
                for entry in extract_thread(continuation_items, mutations):
                    if not entry:
                        return
                    yield entry
                continuation = self._extract_continuation({'contents': continuation_items})
                if continuation:
                    break

        message = self._get_text(root_continuation_data, ('contents', ..., 'messageRenderer', 'text'), max_runs=1)
        if message and not parent and tracker['running_total'] == 0:
            self.report_warning(f'Youtube said: {message}', video_id=video_id, only_once=True)
            raise self.CommentsDisabled

    @staticmethod
    def _generate_comment_continuation(video_id):
        """
        Generates initial comment section continuation token from given video id
        """
        token = f'\x12\r\x12\x0b{video_id}\x18\x062\'"\x11"\x0b{video_id}0\x00x\x020\x00B\x10comments-section'
        return base64.b64encode(token.encode()).decode()

    def _get_comments(self, ytcfg, video_id, contents):
        """Entry for comment extraction"""
        def _real_comment_extract(response):
            yield from self._comment_entries(response, ytcfg, video_id)
        tab = self._extract_tab_renderers(contents)
        continuation_renderer = next(
            (item for item in traverse_obj(tab, (..., 'content', 'sectionListRenderer', 'contents', ..., 'itemSectionRenderer'), default={})
            if item.get('sectionIdentifier') == 'comment-item-section'),
            None
        )
        self._dump_json(contents, "contents")
        headers = self.generate_api_headers(ytcfg=ytcfg, default_client='web')
        #token = traverse_obj(continuation_renderer, ('contents', 0, 'continuationItemRenderer', 'continuationEndpoint', 'continuationCommand'))
        continuation_renderer['contents'][0]['continuationItemRenderer']['continuationEndpoint']['continuationCommand']['token']
        response = self._call_api('browse', {'context': ytcfg['INNERTUBE_CONTEXT'],
         'continuation': continuation_renderer['contents'][0]['continuationItemRenderer']['continuationEndpoint']['continuationCommand']['token']},
          video_id, True, headers, 'Getting comment count for post', 'Oopsies')
        self._dump_json(response, "response")
        max_comments = int(response['onResponseReceivedEndpoints'][0]['reloadContinuationItemsCommand']['continuationItems'][0]['commentsHeaderRenderer']['countText']['runs'][0]['text'])
        return itertools.islice(_real_comment_extract(response), 0, max_comments)
    '''
    @classmethod
    def _extract_next_continuation_data(cls, renderer):
        #next_continuation = try_get(
        #    renderer, (lambda x: x['continuations'][0]['nextContinuationData'],
        #               lambda x: x['continuation']['reloadContinuationData']), dict)
        next_continuation = traverse_obj(renderer, ("onResponseReceivedEndpoints", 1, 'reloadContinuationItemsCommand', 'continuationItems',
                ..., 'continuationItemRenderer'), default={})
        for continuation in next_continuation:
            if continuation.get('trigger') == 'CONTINUATION_TRIGGER_ON_ITEM_SHOWN':
                next_continuation = continuation
        if not next_continuation:
            return
        continuation = next_continuation['continuationEndpoint']['continuationCommand'].get('token')
        if not continuation:
            return
        ctp = next_continuation['continuationEndpoint'].get('clickTrackingParams')
        return cls._build_api_continuation_query(continuation, ctp)
    '''
    @classmethod
    def _extract_next_continuation_data(cls, renderer):
        next_continuation = traverse_obj(renderer, ("onResponseReceivedEndpoints", 0, 'reloadContinuationItemsCommand', 'continuationItems',
                ..., 'commentsHeaderRenderer', 'sortMenu', 'sortFilterSubMenuRenderer', 'subMenuItems', ..., ), default={})
        for continuation in next_continuation:
            if continuation.get('title') == 'Newest first':
                next_continuation = continuation
        if not next_continuation:
            return
        continuation = next_continuation['serviceEndpoint']['continuationCommand'].get('token')
        if not continuation:
            return
        ctp = next_continuation['serviceEndpoint'].get('clickTrackingParams')
        return cls._build_api_continuation_query(continuation, ctp)

    @classmethod
    def _extract_continuation_ep_data(cls, continuation_ep: dict):
        if isinstance(continuation_ep, dict):
            continuation = try_get(
                continuation_ep, lambda x: x['continuationCommand']['token'], str)
            if not continuation:
                return
            ctp = continuation_ep.get('clickTrackingParams')
            return cls._build_api_continuation_query(continuation, ctp)

    @classmethod
    def _extract_continuation(cls, renderer):
        next_continuation = cls._extract_next_continuation_data(renderer)
        if next_continuation:
            return next_continuation

        return traverse_obj(renderer, (
            ('contents', 'items', 'rows'), ..., 'continuationItemRenderer',
            ('continuationEndpoint', ('button', 'buttonRenderer', 'command')),
        ), get_all=False, expected_type=cls._extract_continuation_ep_data)

    #Sorry, for debugging atm, will be removed later
    @staticmethod
    def _dump_json(json_data, file_name):
        with open(f"community-test/{file_name}.json", 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=4)