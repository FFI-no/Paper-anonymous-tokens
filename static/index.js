// Import the WebAssembly memory at the top of the file.
import init, { QrClient } from "./node_modules/token-qr/token_qr.js";

const CELL_SIZE = 5; // px
const QUIET_ZONE = 4; // standard
const DEAD_COLOR = "#FFFFFF";
const ALIVE_COLOR = "#000000";

function create_qr_code(qrclient) {
        const width = qrclient.width();

        // Give the canvas room for all of our cells and a 1px border
        // around each of them.
        const canvas = document.getElementById("game-of-life-canvas");
        canvas.height = CELL_SIZE * (width + 2 * QUIET_ZONE);
        canvas.width = canvas.height;

        const ctx = canvas.getContext('2d');

        const renderLoop = () => {
          drawCells();

          requestAnimationFrame(renderLoop);
        };

        const getIndex = (row, column) => {
          return row * width + column;
        };

        const drawCells = () => {
          ctx.beginPath();

          for (let row = 0; row < width; row++) {
            for (let col = 0; col < width; col++) {
              // const idx = getIndex(row, col);

              ctx.fillStyle = qrclient.is_dark(row, col)
                ? "#000000"
                : "#FFFFFF";

              ctx.fillRect(
                (col + QUIET_ZONE) * CELL_SIZE,
                (row + QUIET_ZONE) * CELL_SIZE,
                CELL_SIZE,
                CELL_SIZE
              );
            }
          }

          ctx.stroke();
        };

        drawCells();
}

function run() {
        init().then(() => {
                document.getElementById("btn-request").onclick = () => {
                        var username = document.getElementById("username").value;
                        var password = document.getElementById("password").value;
                        var resource = document.getElementById("resource").value;

                        var self_signed = document.getElementById("btn-self-sign").checked;
                        
                        const canvas = document.getElementById("game-of-life-canvas");
                        const context = canvas.getContext('2d');
                        context.clearRect(0, 0, canvas.width, canvas.height);

                        try {
                                if (self_signed) {
                                        QrClient.self_signed(resource).then(create_qr_code)
                                } else {
                                        QrClient.new(username, password, resource).then(create_qr_code)
                                }
                        } catch (e) {
                                alert("failed to get token");
                        }
                };
        });
}

run();
