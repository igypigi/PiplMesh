var POSTS_LIMIT = 20;
var POSTS_DATE_UPDATE_INTERVAL = 60000; // ms

function howManyColumns() {
    var panelsWidth = $('#panels').innerWidth();
    var columnPanelsWidth = $('.panels_column').outerWidth();

    return parseInt(panelsWidth / columnPanelsWidth);
}

function movePanel(name, columnIndex) {
    $('#panel-' + name).appendTo($('#panels').children().eq(columnIndex));
}

function initializeEmptyColumnsForPanels() {
    var panels = $('.panel').detach();
    var currentColumns = $('#panels').children().length;
    var numberOfColumns = howManyColumns();

    for (var i = currentColumns; i < numberOfColumns; i++) {
        var newColumn = $('<div/>');
        newColumn.addClass('panels_column');
        $('#panels').append(newColumn);
    }

    var removeColumsFromIndex = numberOfColumns - 1;
    $('#panels').find('.panels_column:gt(' + removeColumsFromIndex + ')').remove();
    panels.appendTo('.panels_column:first');
}

function orderPanelsDefault() {
    var numberOfColumns = howManyColumns();

    $('.panel').each(function (index, panel) {
        var toColumn = index % numberOfColumns;
        var columns = $('#panels').children();

        $(panel).appendTo(columns.eq(toColumn));
    });
}

function sendOrderOfPanelsToServer() {
    var names = [];
    var columns = [];
    var numberOfColumns = 0;

    $('#panels').children().each(function (i, column) {
        numberOfColumns++;
        $(column).children().each(function (j, panel) {
            names.push($(panel).prop('id').substr('panel-'.length));
            columns.push(i);
        });
    });

    if (numberOfColumns) {
        $.post(URLS.panels_order, {
            'names': names,
            'columns': columns,
            'number_of_columns': numberOfColumns
        });
    }
}

function orderPanels() {
    $.getJSON(URLS.panels_order, {
        'number_of_columns': howManyColumns()
    }, function (data, textStatus, jqXHR) {
        if (data.length == 0) {
            orderPanelsDefault();
        }
        else {
            $.each(data, function (i, column) {
                $.each(column, function (j, panel) {
                    movePanel(panel, i);
                });
            });
        }
    });
}

function collapsePanels() {
    $.getJSON(URLS.panels_collapse, function (data, textStatus, jqXHR) {
        $.each(data, function (name, collapsed) {
            if (collapsed) {
                $('#panel-' + name + ' .content').css('display', 'none');
            }
        });
    });
}

function initializePanels() {
    initializeEmptyColumnsForPanels();
    orderPanels();
    collapsePanels();
    makeColumnsSortable();
    makePanelsOrderUpdatable();
}

function makeColumnsSortable() {
    $('.panels_column').sortable({
        'connectWith': '.panels_column',
        'handle': '',
        'cursor': 'move',
        'placeholder': 'placeholder',
        'forcePlaceholderSize': true,
        'opacity': 0.6,
        'helper': 'clone'
    }).disableSelection();
}

function makePanelsOrderUpdatable() {
    $('.panels_column').bind('sortstop', function (event, ui) {
        sendOrderOfPanelsToServer();
    });
}

// Calculates difference between current time and the time when the post was created and generates a message
function formatDiffTime(time) {
    // TODO: Check for cross browser compatibility, currently works in Chrome and Firefox on Ubuntu
    var created_time_diff = (new Date().getTime() - Date.parse(time)) / (60 * 1000); // Converting time from milliseconds to minutes
    if (created_time_diff < 2) { // minutes
        var msg = gettext("just now");
    }
    else if (created_time_diff >= 60 * 24) { // 24 hours, 1 day
        var days = Math.round(created_time_diff / (60 * 24));
        var format = ngettext("%(days)s day ago", "%(days)s days ago", days);
        var msg = interpolate(format, {'days': days}, true);
    }
    else if (created_time_diff >= 60) { // 60 minutes, 1 hour
        var hours = Math.round(created_time_diff / 60);
        var format = ngettext("%(hours)s hour ago", "%(hours)s hours ago", hours);
        var msg = interpolate(format, {'hours': hours}, true);
    }
    else {
        var minutes = Math.round(created_time_diff);
        var format = ngettext("%(minutes)s minute ago", "%(minutes)s minutes ago", minutes);
        var msg = interpolate(format, {'minutes': minutes}, true);
    }
    return msg;
}

function Post(data) {
    var self = this;
    $.extend(self, data);

    function createDOM() {
        // TODO: Improve and add other post options

        var post = $('<li/>').addClass('post').data('post', self);

        var delete_link = $('<li/>').append(
            $('<a/>').addClass('delete-post').addClass('hand').text(gettext("Delete"))
        );

        var hug_link = $('<a/>').addClass('hand').text(gettext("Hug"));
        var hug = $('<li/>').addClass('hug').append(hug_link);
        var run_link = $('<a/>').addClass('hand').append(gettext("Run"));
        var run = $('<li/>').addClass('run').append(run_link);

        $.each(self.hugs, function (index, value){
            if(user.username == value){
                hug_link.data('selected', true);
                hug_link.css('font-weight', 'bold').text(gettext("Unhug"));
            }
        });

        $.each(self.runs, function (index, value){
            if(user.username == value){
                run_link.data('selected', true);
                run_link.css('font-weight', 'bold').text(gettext("Unrun"));
            }
        });

        function hug_run_link_click (link1, link2, type, text1, text1b, text2) {
            link1.click(function (event) {
                var selected = link1.data('selected');
                if (!selected) {
                    $.post(URLS.hug_run, {
                        'type': type,
                        'id': post.data('post').id
                    }, function () {
                        link1.data('selected', true);
                        link1.css('font-weight', 'bold').text(text1b);
                        link2.data('selected', false);
                        link2.css('font-weight', 'normal').text(text2);
                    });
                }
                else {
                    $.post(URLS.hug_run, {
                        'type': 'un'+type,
                        'id': post.data('post').id
                    }, function () {
                        link1.data('selected', false);
                        link1.css('font-weight', 'normal').text(text1);
                        link2.data('selected', false);
                        link2.css('font-weight', 'normal').text(text2);
                    });
                }
            });
        }

        hug_run_link_click(hug_link, run_link, 'hug', gettext("Hug"), gettext("Unhug"), gettext("Run"));
        hug_run_link_click(run_link, hug_link, 'run', gettext("Run"), gettext("Unrun"), gettext("Hug"));

        var post_options = $('<ul />').addClass('options').append(delete_link).append(hug).append(run);

        var huggers = $('<ul/>');
        if (!self.hugs) {
            huggers.append(
                $('<li/>').addClass('first').text(gettext("No huggers"))
            );
        } else {
            huggers.append(
                $('<li/>').addClass('first').text(gettext("Huggers:"))
            );
            $.each(self.hugs, function (index, value){
                huggers.append($('<li/>').text(value));
            });
        }

        var runners = $('<ul/>');
        if (!self.runs) {
            runners.append(
                $('<li/>').addClass('first').text(gettext("No runners"))
            );
        } else {
            runners.append(
                $('<li/>').addClass('first').text(gettext("Runners:"))
            );
            $.each(self.runs, function (index, value){
                runners.append($('<li/>').text(value));
            });
        }

        hugs_runs = $('<div/>').addClass('hugs_runs').text(self.hugs.length + gettext(" hugs, ") + self.runs.length
            + gettext(" runs") )
            .append($('<div/>').addClass('hugs_runs_display').append(huggers).append(runners)
        );

        hugs_runs.hover(function (event) {
                $('.hugs_runs_display', this).show();
            },
            function (event) {
                $('.hugs_runs_display', this).hide();
            });

        post.append(post_options).append(
            $('<span/>').addClass('author').text(self.author.username)
        ).append(
            $('<p/>').addClass('content').text(self.message)
        ).append(
            $('<div/>').addClass('footer').append(
                $('<span/>').addClass('date').text(formatDiffTime(self.created_time))
            ).append(
                hugs_runs
            )
        );

        return post;
    }

    function checkIfPostExists() {
        return $('.post').is(function (index) {
            return $(this).data('post').id == self.id;
        });
    }

    self.addToBottom = function () {
        if (checkIfPostExists()) return;

        $('.posts').append(createDOM());
    };

    self.addToTop = function () {
        if (checkIfPostExists()) return;

        // TODO: Animation has to be considered and maybe improved
        createDOM(data).prependTo($('.posts')).hide().slideToggle('slow');
    };

    self.updateDate = function (dom_element) {
        $(dom_element).find('.date').text(formatDiffTime(self.created_time));
    }

    self.updatePost = function () {
        if (checkIfPostExists()){
            $('.post').filter(function () {
                return $(this).data('post') && $(this).data('post').id == self.id
                    && $(this).data('post').updated_time < self.updated_time;
            }).replaceWith(generateHtml());
        }
        else {
            generateHtml(data).prependTo($('.posts')).hide().slideToggle('slow');
        }
    }
}

function loadPosts(offset) {
    $.getJSON(URLS.post, {
        'limit': POSTS_LIMIT,
        'offset': offset
    }, function (data, textStatus, jqXHR) {
        $.each(data.objects, function (i, post) {
            new Post(post).addToBottom();
        });
    });
}

function Notification(data) {
    var self = this;
    $.extend(self, data);

    function createDOM() {
        var format = gettext("%(author)s commented on post.");
        var author = interpolate(format, {'author': self.comment.author.username}, true);

        var notification = $('<li/>').addClass('notification').data('notification', self).append(
            $('<span/>').addClass('notification_element').text(author)
        ).append(
            $('<span/>').addClass('notification_message').addClass('notification_element').text(self.comment.message)
        ).append(
            $('<span/>').addClass('notification_element').addClass('notification_created_time').text(formatDiffTime(self.created_time))
        );

        return notification;
    }

    function checkIfNotificationExists() {
        return $('.notification').is(function (index) {
            return $(this).data('notification').id == self.id;
        });
    }

    self.add = function () {
        if (checkIfNotificationExists()) return;

        if (!self.read) {
            $('#notifications_count').text(parseInt($('#notifications_count').text()) + 1);
        }
        $('#notifications_list').prepend(createDOM());
    };

    self.updateDate = function (dom_element) {
        $(dom_element).find('.notification_created_time').text(formatDiffTime(self.created_time));
    }
}

function loadNotifications() {
    $.getJSON(URLS.notifications, function (data, textStatus, jqXHR) {
        $.each(data.objects, function (i, notification) {
            new Notification(notification).add();
        });
    });
}

// TODO: This is just for testing purposes. It can be base for future development.
function addComment(comment) {
    // TODO: Change this for any post
    var post_url = $('.post').first().data('post').resource_uri;

    $.ajax({
        type: 'POST',
        // TODO: Should probably not construct URL like that
        url: post_url + 'comments/',
        data: JSON.stringify({'message': comment}),
        contentType: 'application/json',
        dataType: 'json',
        success: function (data, textStatus, jqXHR) {
            alert("Comment posted.");
        }
    });
}

$(document).ready(function () {
    initializePanels();

    $.updates.registerProcessor('home_channel', 'post_new', function (data) {
        new Post(data.post).addToTop();
    });
    $.updates.registerProcessor('home_channel', 'post_update', function (data) {
        var post = new Post(data.post);
        post.updatePost();
    });

    $('.panel .header').click(function (event) {
        var collapsed = $(this).next().is(':visible');
        $(this).next('.content').slideToggle('fast');

        var name = $(this).parent().prop('id').substr('panel-'.length);

        $.post(URLS.panels_collapse, {
            'name': name,
            'collapsed': collapsed
        });
    });

    // TODO: Ajax request to store panels state is currently send many times while resizing, it should be send only at the end
    $(window).resize(function (event) {
        initializePanels();
    });

    // Saving text from post input box
    var input_box_text = $('#post_text').val();

    // Shows last updated posts, starting at offset 0, limited by POSTS_LIMIT
    loadPosts(0);

    $('#submit_post').click(function (event) {
        var message = $('#post_text').val();
        $(this).prop('disabled', true);
        var is_published = true;
        $.ajax({
            'type': 'POST',
            'url': URLS.post,
            'data': JSON.stringify({
                'message': message,
                'is_published': is_published
            }),
            'contentType': 'application/json',
            'dataType': 'json',
            'success': function (data, textStatus, jqXHR) {
                $('#post_text').val(input_box_text).css('min-height', 25);
            },
            'error': function (jqXHR, textStatus, errorThrown) {
                // There was an error, we enable form back
                $('#submit_post').prop('disabled', false);
            }
        });
    });

    $('#post_text').expandingTextArea().focus(function (event) {
        if ($(this).val() == input_box_text) {
            $(this).val('');
        }
        $(this).css('min-height', 50);
    }).blur(function (event) {
        if (!$(this).val().trim()) {
            $(this).val(input_box_text);
            $(this).css('min-height', 25);
        }
    }).keyup(function (event) {
        if (!$(this).val().trim()) {
            $('#submit_post').prop('disabled', true);
        }
        else {
            $('#submit_post').prop('disabled', false);
        }
    });

    $(window).scroll(function (event) {
        if (document.body.scrollHeight - $(this).scrollTop() <= $(this).height()) {
            var last_post = $('.post:last').data('post');
            if (last_post) {
                loadPosts(last_post.id);
            }
        }
    });

    // Notifications
    $('#notifications_count').add('.close_notifications_box').click(function (event) {
        $('#notifications_box').slideToggle('fast');
    });
    // TODO: Just for testing
    $('#add_comment').click(function (event) {
        addComment("Test comment");
    });

    $.updates.registerProcessor('user_channel', 'notification', function (data) {
        new Notification(data.notification).add();
    });

    loadNotifications();

    // TODO: Improve date updating so that interval is set on each date individually
    setInterval(function () {
        $('.post').each(function (i, post) {
            $(post).data('post').updateDate(this);
        });
        $('.notification').each(function (i, notification) {
            $(notification).data('notification').updateDate(this);
        });
    }, POSTS_DATE_UPDATE_INTERVAL);
});