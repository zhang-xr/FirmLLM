const customCSS = `
        ::-webkit-scrollbar {
            width: 10px;
        }
        ::-webkit-scrollbar-track {
            background: #27272a;
        }
        ::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 0.375rem;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
    `;

    const styleTag = document.createElement("style");
    styleTag.textContent = customCSS;
    document.head.append(styleTag);

    let labels = [];

    function unmarkPage() {
    // Unmark page logic
    for (const label of labels) {
        document.body.removeChild(label);
    }
    labels = [];
    }

    function markPage() {
    unmarkPage();

    var bodyRect = document.body.getBoundingClientRect();

    var items = Array.prototype.slice
        .call(document.querySelectorAll("*"))
        .map(function (element) {
        var vw = Math.max(
            document.documentElement.clientWidth || 0,
            window.innerWidth || 0
        );
        var vh = Math.max(
            document.documentElement.clientHeight || 0,
            window.innerHeight || 0
        );
        var textualContent = element.textContent.trim().replace(/\s{2,}/g, " ");
        var elementType = element.tagName.toLowerCase();
        var ariaLabel = element.getAttribute("aria-label") || "";

        var rects = [...element.getClientRects()]
            .filter((bb) => {
            var center_x = bb.left + bb.width / 2;
            var center_y = bb.top + bb.height / 2;
            var elAtCenter = document.elementFromPoint(center_x, center_y);

            return elAtCenter === element || element.contains(elAtCenter);
            })
            .map((bb) => {
            const rect = {
                left: Math.max(0, bb.left),
                top: Math.max(0, bb.top),
                right: Math.min(vw, bb.right),
                bottom: Math.min(vh, bb.bottom),
            };
            return {
                ...rect,
                width: rect.right - rect.left,
                height: rect.bottom - rect.top,
            };
            });

        var area = rects.reduce((acc, rect) => acc + rect.width * rect.height, 0);

        return {
            element: element,
            include:
            element.tagName === "SELECT" ||
            element.tagName === "BUTTON" ||
            element.tagName === "A" ||
            element.onclick != null ||
            window.getComputedStyle(element).cursor == "pointer" ||
            element.tagName === "IFRAME",
            area,
            rects,
            text: textualContent,
            type: elementType,
            ariaLabel: ariaLabel,
        };
        })
        .filter((item) => item.include && item.area >= 80);

    // Only keep inner clickable items
    items = items.filter(
        (x) => !items.some((y) => x.element.contains(y.element) && !(x == y))
    );
    // Color scheme to distinguish valid links and normal A tags
    const COLOR_SCHEME = {
        'a-link': "#FF4444",     // Valid links in red
        'a': "#FFA07A",          // Normal A tags in light red
        'button': "#4CAF50",     // Buttons in green
        'select': "#9C27B0",     // Select boxes in purple
        'iframe': "#2196F3",     // Iframes in blue
        'clickable': "#FF9800",  // Other clickable elements in orange
    };
    // Modify color logic in items.forEach
    items.forEach(function (item, index) {
        item.rects.forEach((bbox) => {
            newElement = document.createElement("div");
            
            // Get element type and color
            const elementType = item.element.tagName.toLowerCase();
            let borderColor;
            
            if (elementType === 'a') {
                // Check if it's a valid link
                const href = item.element.getAttribute('href');
                const isValidLink = href && href !== '#' && href !== '';
                borderColor = isValidLink ? COLOR_SCHEME['a-link'] : COLOR_SCHEME['a'];
            } else {
                borderColor = COLOR_SCHEME[elementType] || 
                             (item.element.onclick || window.getComputedStyle(item.element).cursor === "pointer" 
                              ? COLOR_SCHEME.clickable 
                              : "#757575");
            }
            
            newElement.style.outline = `1px dashed ${borderColor}`;
            newElement.style.position = "fixed";
            newElement.style.left = bbox.left + "px";
            newElement.style.top = bbox.top + "px";
            newElement.style.width = bbox.width + "px";
            newElement.style.height = bbox.height + "px";
            newElement.style.pointerEvents = "none";
            newElement.style.boxSizing = "border-box";
            newElement.style.zIndex = 2147483647;

            // Use the same color for the label
            var label = document.createElement("span");
            label.textContent = index;
            label.style.position = "absolute";
            label.style.top = "-19px";
            label.style.left = "0px";
            label.style.background = borderColor;
            label.style.color = "white";
            label.style.padding = "2px 4px";
            label.style.fontSize = "12px";
            label.style.borderRadius = "2px";
            newElement.appendChild(label);

            document.body.appendChild(newElement);
            labels.push(newElement);
        });
    });
    const coordinates = items.flatMap((item) =>
        item.rects.map(({ left, top, width, height }) => ({
        x: (left + left + width) / 2,
        y: (top + top + height) / 2,
        type: item.type,
        text: item.text,
        ariaLabel: item.ariaLabel,
        }))
    );
    return coordinates;
    }
