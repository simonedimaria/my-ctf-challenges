var hitBtn = $('button.damage'),
    reset = $('button.reset'),
    hBar = $('.health-bar'),
    bar = hBar.find('.bar'),
    hit = hBar.find('.hit'),
    isPlaying = true,
    audio = new Audio('/static/audio/main.mp3');

const reduceHealth = () => {
    var total = hBar.data('total'),
        value = hBar.data('value');

    var damage = 50;

    var newValue = value - damage;

    var barWidth = (newValue / total) * 100;
    var hitWidth = (damage / value) * 100 + "%";

    hit.css('width', hitWidth);
    hBar.data('value', newValue);

    setTimeout(function () {
        hit.css({ 'width': '0' });
        bar.css('width', barWidth + "%");
    }, 500);
}

const restoreHealth = () => {

    hBar.data('value', hBar.data('total'));

    hit.css({ 'width': '0' });

    bar.css('width', '100%');
}

const playAudio = () => {
    audio.play();
    $('#vol').attr('src', '/static/img/vol.svg');
    isPlaying = true;
}

const muteAudio = () => {
    audio.pause();
    $('#vol').attr('src', '/static/img/mute.svg');
    isPlaying = false;
}

const toggleVol = () => {
    isPlaying ? muteAudio() : playAudio();
}

const restart = () => {
    fetch('/restart')
        .then(data => data.json())
        .then((res) => {
            if (res.ok) {
                $('#flag').text('Restart Complete!');
                $('#flag').css('display', 'block');

                setTimeout(function () {
                    $('#flag').css('display', 'none');
                }, 4000)
            };
        })
}

const flag = () => {
    reduceHealth()
    fetch('/flag')
        .then(res => {
            if (res.status === 200) {
                res.text()
                    .then(d => {
                        $('#flag').text(d);
                        $('#flag').css('display', 'block');

                        setTimeout(function () {
                            $('#flag').css('display', 'none');
                        }, 4000)
                    });
            }
            else {
                $('#error').css('display', 'block');

                setTimeout(function () {
                    $('#error').css('display', 'none');
                }, 4000)
            }
        })
}

setInterval(function () {
    restoreHealth();
}, 2000);

$(window).ready(function () {
    audio.loop = true;
    audio.play();
});