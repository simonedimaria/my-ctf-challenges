var connectionInfo;

$.getJSON('/connection_info',
    function (data) {
        connectionInfo = JSON.stringify(data, null, 4);
        $('#jsonCode').html(syntaxHighlight(connectionInfo));
    }
);

function syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        var cls = 'number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'key';
            } else {
                cls = 'string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'boolean';
        } else if (/null/.test(match)) {
            cls = 'null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

const copyToClipboard = () => {
    navigator.clipboard.writeText(connectionInfo);
    $('#showalert').css('display', 'block');

    setTimeout(function(){
        $('#showalert').css('display', 'none');
    }, 3000)
}

const restart = () => {
    fetch('/restart')
        .then(data => data.json())
        .then((res) => {
            if (res.ok) {
                location.reload();
                $('#showalert').text('Restart Completed!');
                $('#showalert').css('display', 'block');

                setTimeout(function () {
                    $('#showalert').css('display', 'none');
                }, 4000)
            };
        })
}
