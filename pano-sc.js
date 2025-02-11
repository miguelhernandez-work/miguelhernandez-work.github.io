(function() {
    //version 1.7 - now loaded via a bookmarklet reading a github file 'miguelhernandez-work.github.io/pano-sc.js'
    let cachedPreviews = {};
    let lastHoveredItem = null;
    let highestZIndex = 10000;
    let modalOffset = { x: 50, y: 50 };
    const X_PAN_KEY = "xxxxxx";


    function showHoverPreview(member, event) {
        lastHoveredItem = member;
        if (cachedPreviews[member]) {
            renderHoverPreview(cachedPreviews[member], event);
            return;
        }
        fetchObjectData(member, (data) => renderHoverPreview(data, event));
    }

    function fetchObjectData(member, callback) {
        let url1 = `https://panorama1.asp.cloudwerxdata.com/restapi/v11.0/Objects/Addresses?location=shared&name=${member}`;
        let url2 = `https://panorama1.asp.cloudwerxdata.com/restapi/v11.0/Objects/AddressGroups?location=shared&name=${member}`;

        fetch(url1, { headers: { "X-PAN-KEY": X_PAN_KEY } })
            .then(response => response.json())
            .then(data => {
                if (data.result?.entry?.length > 0) {
                    cachedPreviews[member] = data.result.entry[0];
                    callback(data.result.entry[0]);
                } else {
                    fetch(url2, { headers: { "X-PAN-KEY": X_PAN_KEY} })
                        .then(response => response.json())
                        .then(data => {
                            if (data.result?.entry?.length > 0) {
                                cachedPreviews[member] = data.result.entry[0];
                                callback(data.result.entry[0]);
                            } else {
                                callback({ "@name": member, "error": "Not found" });
                            }
                        })
                        .catch(error => console.error("Error fetching AddressGroup:", error));
                }
            })
            .catch(error => console.error("Error fetching Address:", error));
    }

    function renderHoverPreview(data, event) {
        let preview = document.getElementById("hoverPreview");
        if (!preview) {
            preview = document.createElement("div");
            preview.id = "hoverPreview";
            preview.style.position = "absolute";
            preview.style.background = "white";
            preview.style.border = "1px solid #ccc";
            preview.style.padding = "5px";
            preview.style.borderRadius = "5px";
            preview.style.fontSize = "12px";
            preview.style.boxShadow = "2px 2px 10px rgba(0,0,0,0.2)";
            preview.style.zIndex = highestZIndex + 2;
            document.body.appendChild(preview);
        }
        let content = `<h3>${data["@name"]}</h3><br>`;
        if (data["ip-netmask"]) {
            content += `IP: ${data["ip-netmask"]}`;
        } else if (data.static?.member) {
            content += `Members: ${data.static.member.join(", ")}`;
        } else {
            content += "No details available";
        }
        preview.innerHTML = content;
        preview.style.left = `${event.pageX + 10}px`;
        preview.style.top = `${event.pageY + 10}px`;
        preview.style.display = "block";
        preview.style.zIndex = highestZIndex + 2;
    }

    function hideHoverPreview() {
        let preview = document.getElementById("hoverPreview");
        if (preview) preview.style.display = "none";
    }

    function determineObjectTypeAndFetch(member) {
        if (cachedPreviews[member]) {
            showDraggableModal(cachedPreviews[member]);
        } else {
            fetchObjectData(member, showDraggableModal);
        }
    }

    function bringToFront(modal) {
        highestZIndex++;
        modal.style.zIndex = highestZIndex;
    }

    function showDraggableModal(data, searchable = false) {
        let modal = document.createElement("div");
        modal.style.position = "absolute";
        modal.style.top = `${modalOffset.y}px`;
        modal.style.left = `${modalOffset.x}px`;
        modal.style.width = "400px";
        modal.style.height = "300px";
        modal.style.background = "white";
        modal.style.border = "1px solid #ccc";
        modal.style.borderRadius = "8px";
        modal.style.boxShadow = "2px 2px 10px rgba(0,0,0,0.2)";
        modal.style.overflow = "hidden";
        modal.style.zIndex = ++highestZIndex;
        modal.style.resize = "both";

        modalOffset.x += 30;
        modalOffset.y += 30;
        if (modalOffset.x > window.innerWidth - 450 || modalOffset.y > window.innerHeight - 350) {
            modalOffset.x = 50;
            modalOffset.y = 50;
        }

        let titleBar = document.createElement("div");
        titleBar.style.background = "#007bff";
        titleBar.style.color = "white";
        titleBar.style.padding = "5px 10px";
        titleBar.style.cursor = "move";
        titleBar.style.display = "flex";
        titleBar.style.alignItems = "center";
        titleBar.style.justifyContent = "space-between";
        titleBar.style.boxSizing = "border-box";
        titleBar.style.width = "100%";
        titleBar.style.position = "sticky";

        let titleText = document.createElement("span");
        if (data["@name"]) {titleText.innerText = data["@name"];}

        let controlsDiv = document.createElement("div");
        controlsDiv.style.display = "flex";
        controlsDiv.style.alignItems = "center";
        controlsDiv.style.marginRight = "50px";

        let closeButton = document.createElement("span");
        closeButton.innerHTML = "✖";
        closeButton.style.cursor = "pointer";
        closeButton.style.fontWeight = "bold";
        closeButton.style.marginLeft = "10px";
        closeButton.onclick = () => modal.remove();

        if (searchable) {
            let searchBox = document.createElement("input");
            searchBox.type = "text";
            searchBox.placeholder = "Find...";
            searchBox.style.marginLeft = "10px";
            searchBox.style.padding = "3px";
            searchBox.style.borderRadius = "3px";
            searchBox.style.border = "none";
            searchBox.addEventListener("keydown", function(event) {
    					if (event.key === "Enter") {
        				event.preventDefault();
        				searchInList(modal, searchBox.value, true);
    					}
						});

            let findNextButton = document.createElement("button");
            findNextButton.innerText = "▶";
            findNextButton.style.marginLeft = "5px";
            findNextButton.style.padding = "3px";
            findNextButton.style.cursor = "pointer";
            findNextButton.onclick = () => searchInList(modal, searchBox.value, true);

            let findPrevButton = document.createElement("button");
            findPrevButton.innerText = "◀";
            findPrevButton.style.marginLeft = "3px";
            findPrevButton.style.padding = "3px";
            findPrevButton.style.cursor = "pointer";
            findPrevButton.onclick = () => searchInList(modal, searchBox.value, false);

            controlsDiv.appendChild(searchBox);
            controlsDiv.appendChild(findPrevButton);
            controlsDiv.appendChild(findNextButton);
        }

        controlsDiv.appendChild(closeButton);
        titleBar.appendChild(titleText);
        titleBar.appendChild(controlsDiv);
        modal.appendChild(titleBar);
        

        let content = document.createElement("div");
        content.style.padding = "10px";
        content.style.height = "calc(100% - 55px)";
        content.style.overflowY = "auto";

        if (data["ip-netmask"]) {
            content.innerHTML += `<p><strong>IP:</strong> ${data["ip-netmask"]}</p>`;
        } else if (Array.isArray(data.entry)) {
            titleBar.prepend(document.createTextNode("Addresses"));
            let list = document.createElement("ul");
            data.entry.forEach(addr => {
                let listItem = document.createElement("li");
                listItem.innerText = `${addr["@name"]}: ${addr["ip-netmask"] || "N/A"}`;
                list.appendChild(listItem);
            });
            content.appendChild(list);
        } else if (data.static?.member) {
            let list = document.createElement("ul");
            data.static.member.forEach(member => {
                let listItem = document.createElement("li");
                let link = document.createElement("a");
                link.href = "#";
                link.innerText = member;
                link.style.color = "#007bff";
                link.onmouseover = (e) => showHoverPreview(member, e);
                link.onmouseout = hideHoverPreview;
                link.onclick = (event) => {
                    event.preventDefault();
                    determineObjectTypeAndFetch(member);
                };
                listItem.appendChild(link);
                list.appendChild(listItem);
            });
            content.appendChild(list);
        } else {
            content.innerHTML = `<pre>${data}</pre>`;
        }
        modal.appendChild(content);
        document.body.appendChild(modal);
        makeDraggable(modal, titleBar);
        bringToFront(modal);
    }

    function searchInList(modal, searchText, forward) {
        if (!searchText) return;

        let listItems = modal.querySelectorAll("li");
        let currentIndex = Array.from(listItems).findIndex(li => li.style.background === "yellow");

        if (currentIndex !== -1) {
            listItems[currentIndex].style.background = "";
        }

        let newIndex = forward ? currentIndex + 1 : currentIndex - 1;
        if (newIndex < 0) newIndex = listItems.length - 1;
        if (newIndex >= listItems.length) newIndex = 0;

        for (let i = 0; i < listItems.length; i++) {
            let indexToCheck = (newIndex + i) % listItems.length;
            if (listItems[indexToCheck].innerText.toLowerCase().includes(searchText.toLowerCase())) {
                listItems[indexToCheck].style.background = "yellow";
                listItems[indexToCheck].scrollIntoView({ behavior: "smooth", block: "center" });
                break;
            }
        }
    }
    function makeDraggable(modal, titleBar) {
        let offsetX = 0, offsetY = 0, isDragging = false;
        titleBar.onmousedown = (e) => {
            isDragging = true;
            offsetX = e.clientX - modal.offsetLeft;
            offsetY = e.clientY - modal.offsetTop;
            bringToFront(modal);
            document.onmousemove = (e) => {
                if (isDragging) {
                    modal.style.left = `${e.clientX - offsetX}px`;
                    modal.style.top = `${e.clientY - offsetY}px`;
                }
            };
            document.onmouseup = () => isDragging = false;
        };
    }

    fetch("https://panorama1.asp.cloudwerxdata.com/restapi/v11.0/Objects/AddressGroups?location=shared", { 
        headers: { "X-PAN-KEY": X_PAN_KEY }
    })
    .then(response => response.json())
    .then(data => {
        let groups = data.result.entry;
        showDraggableModal({ "@name": "Address Groups", static: { member: groups.map(g => g["@name"]) } },true);
    })
    .catch(error => showDraggableModal({ "@name": "Error", "details": error.toString() }));

    fetch("https://panorama1.asp.cloudwerxdata.com/restapi/v11.0/Objects/Addresses?location=shared", { 
        headers: { "X-PAN-KEY": X_PAN_KEY }
    })
    .then(response => response.json())
    .then(data => showDraggableModal(data.result,true))
    .catch(error => showDraggableModal({ "@name": "Error", "details": error.toString() }));
})();